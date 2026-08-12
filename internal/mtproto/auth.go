package mtproto

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"
)

const (
	ctorVector             = 0x1CB5C415
	ctorPQInnerDataDC      = 0xA9F55F95
	ctorReqDHParams        = 0xD712E4BE
	ctorServerDHParamsOK   = 0xD0E8075C
	ctorServerDHParamsFail = 0x79CB045D
	ctorServerDHInnerData  = 0xB5890DBA
	ctorClientDHInnerData  = 0x6643B654
	ctorSetClientDHParams  = 0xF5045F1F
	ctorDHGenOK            = 0x3BCBF734
	ctorDHGenRetry         = 0x46DC1FB9
	ctorDHGenFail          = 0xA69DAE02
	ctorRPCError           = 0x2144CA19
)

type authKey struct {
	key        []byte
	keyID      []byte
	salt       []byte
	timeOffset int64
}

func createAuthKey(s *stream, dcID int) (*authKey, error) {
	nonce, err := randomBytes(16)
	if err != nil {
		return nil, err
	}

	if err := s.sendUnencrypted(reqPQMultiBody(nonce)); err != nil {
		return nil, err
	}
	res, err := s.recvUnencrypted()
	if err != nil {
		return nil, fmt.Errorf("no resPQ: %w", err)
	}
	pq, serverNonce, fingerprints, err := parseResPQ(res, nonce)
	if err != nil {
		return nil, err
	}

	p, q, err := factorize(pq)
	if err != nil {
		return nil, err
	}
	key, err := selectKey(fingerprints)
	if err != nil {
		return nil, err
	}
	newNonce, err := randomBytes(32)
	if err != nil {
		return nil, err
	}

	inner := &buf{}
	inner.uint32(ctorPQInnerDataDC)
	inner.bytes(bigEndian(pq))
	inner.bytes(bigEndian(p))
	inner.bytes(bigEndian(q))
	inner.raw(nonce)
	inner.raw(serverNonce)
	inner.raw(newNonce)
	inner.uint32(uint32(dcID))

	encrypted, err := rsaPad(inner.done(), key)
	if err != nil {
		return nil, err
	}

	req := &buf{}
	req.uint32(ctorReqDHParams)
	req.raw(nonce)
	req.raw(serverNonce)
	req.bytes(bigEndian(p))
	req.bytes(bigEndian(q))
	req.uint64(key.fingerprint)
	req.bytes(encrypted)
	if err := s.sendUnencrypted(req.done()); err != nil {
		return nil, err
	}

	res, err = s.recvUnencrypted()
	if err != nil {
		return nil, fmt.Errorf("no server_DH_params: %w", err)
	}
	tmpKey, tmpIV := dhTempKeys(newNonce, serverNonce)
	g, dhPrime, gA, serverTime, err := parseServerDHParams(res, nonce, serverNonce, tmpKey, tmpIV)
	if err != nil {
		return nil, err
	}
	if err := checkDHParams(g, dhPrime, gA); err != nil {
		return nil, err
	}

	b, err := randomBigInt(2048)
	if err != nil {
		return nil, err
	}
	gB := new(big.Int).Exp(big.NewInt(int64(g)), b, dhPrime)

	clientInner := &buf{}
	clientInner.uint32(ctorClientDHInnerData)
	clientInner.raw(nonce)
	clientInner.raw(serverNonce)
	clientInner.uint64(0)
	clientInner.bytes(padTo(gB, 256))

	encryptedClient, err := encryptDHInner(clientInner.done(), tmpKey, tmpIV)
	if err != nil {
		return nil, err
	}

	set := &buf{}
	set.uint32(ctorSetClientDHParams)
	set.raw(nonce)
	set.raw(serverNonce)
	set.bytes(encryptedClient)
	if err := s.sendUnencrypted(set.done()); err != nil {
		return nil, err
	}

	res, err = s.recvUnencrypted()
	if err != nil {
		return nil, fmt.Errorf("no dh_gen answer: %w", err)
	}

	shared := padTo(new(big.Int).Exp(gA, b, dhPrime), 256)
	if err := verifyDHGen(res, nonce, serverNonce, newNonce, shared); err != nil {
		return nil, err
	}

	keyHash := sha1.Sum(shared)
	return &authKey{
		key:        shared,
		keyID:      keyHash[12:20],
		salt:       xor(newNonce[:8], serverNonce[:8]),
		timeOffset: int64(serverTime) - time.Now().Unix(),
	}, nil
}

func reqPQMultiBody(nonce []byte) []byte {
	b := &buf{}
	b.uint32(ctorReqPQMulti)
	b.raw(nonce)
	return b.done()
}

func parseResPQ(payload, nonce []byte) (pq uint64, serverNonce []byte, fingerprints []uint64, err error) {
	c := newCursor(payload)
	c.expect(ctorResPQ, "resPQ")
	if !bytes.Equal(c.int128(), nonce) && c.err == nil {
		return 0, nil, nil, errors.New("resPQ nonce mismatch")
	}
	serverNonce = c.int128()
	pqBytes := c.bytes()
	fingerprints = c.vectorLong()
	if c.err != nil {
		return 0, nil, nil, c.err
	}
	if len(pqBytes) == 0 || len(pqBytes) > 8 {
		return 0, nil, nil, fmt.Errorf("implausible pq length %d", len(pqBytes))
	}
	return bigFromBytes(pqBytes).Uint64(), serverNonce, fingerprints, nil
}

func dhTempKeys(newNonce, serverNonce []byte) (key, iv []byte) {
	newServer := sha1.Sum(append(append([]byte{}, newNonce...), serverNonce...))
	serverNew := sha1.Sum(append(append([]byte{}, serverNonce...), newNonce...))
	newNew := sha1.Sum(append(append([]byte{}, newNonce...), newNonce...))

	key = append(append([]byte{}, newServer[:]...), serverNew[:12]...)
	iv = append(append([]byte{}, serverNew[12:20]...), newNew[:]...)
	iv = append(iv, newNonce[:4]...)
	return key, iv
}

func parseServerDHParams(payload, nonce, serverNonce, tmpKey, tmpIV []byte) (g int, dhPrime, gA *big.Int, serverTime uint32, err error) {
	c := newCursor(payload)
	c.expect(ctorServerDHParamsOK, "server_DH_params_ok")
	if !bytes.Equal(c.int128(), nonce) && c.err == nil {
		return 0, nil, nil, 0, errors.New("server_DH_params nonce mismatch")
	}
	if !bytes.Equal(c.int128(), serverNonce) && c.err == nil {
		return 0, nil, nil, 0, errors.New("server_DH_params server_nonce mismatch")
	}
	answer := c.bytes()
	if c.err != nil {
		return 0, nil, nil, 0, c.err
	}

	decrypted, err := igeDecrypt(answer, tmpKey, tmpIV)
	if err != nil {
		return 0, nil, nil, 0, err
	}
	if len(decrypted) < 20 {
		return 0, nil, nil, 0, errors.New("server_DH_inner_data is too short")
	}

	inner := newCursor(decrypted[20:])
	inner.expect(ctorServerDHInnerData, "server_DH_inner_data")
	if !bytes.Equal(inner.int128(), nonce) && inner.err == nil {
		return 0, nil, nil, 0, errors.New("server_DH_inner_data nonce mismatch")
	}
	if !bytes.Equal(inner.int128(), serverNonce) && inner.err == nil {
		return 0, nil, nil, 0, errors.New("server_DH_inner_data server_nonce mismatch")
	}
	g = int(inner.uint32())
	primeBytes := inner.bytes()
	gABytes := inner.bytes()
	serverTime = inner.uint32()
	if inner.err != nil {
		return 0, nil, nil, 0, inner.err
	}

	consumed := decrypted[20 : 20+inner.i]
	if want := sha1.Sum(consumed); !bytes.Equal(want[:], decrypted[:20]) {
		return 0, nil, nil, 0, errors.New("server_DH_inner_data hash mismatch")
	}
	return g, bigFromBytes(primeBytes), bigFromBytes(gABytes), serverTime, nil
}

func encryptDHInner(data, tmpKey, tmpIV []byte) ([]byte, error) {
	hash := sha1.Sum(data)
	payload := append(append([]byte{}, hash[:]...), data...)
	if pad := (16 - len(payload)%16) % 16; pad > 0 {
		filler, err := randomBytes(pad)
		if err != nil {
			return nil, err
		}
		payload = append(payload, filler...)
	}
	return igeEncrypt(payload, tmpKey, tmpIV)
}

func verifyDHGen(payload, nonce, serverNonce, newNonce, shared []byte) error {
	c := newCursor(payload)
	c.expect(ctorDHGenOK, "dh_gen_ok")
	if !bytes.Equal(c.int128(), nonce) && c.err == nil {
		return errors.New("dh_gen_ok nonce mismatch")
	}
	if !bytes.Equal(c.int128(), serverNonce) && c.err == nil {
		return errors.New("dh_gen_ok server_nonce mismatch")
	}
	got := c.int128()
	if c.err != nil {
		return c.err
	}

	auxHash := sha1.Sum(shared)
	digest := sha1.Sum(concat(newNonce, []byte{1}, auxHash[:8]))
	if !bytes.Equal(got, digest[4:20]) {
		return errors.New("dh_gen_ok new_nonce_hash mismatch: the shared key differs")
	}
	return nil
}

var primeCache sync.Map

func checkDHParams(g int, dhPrime, gA *big.Int) error {
	if g < 2 || g > 7 {
		return fmt.Errorf("g is out of range: %d", g)
	}
	if dhPrime.BitLen() != 2048 {
		return fmt.Errorf("dh_prime is %d bits, want 2048", dhPrime.BitLen())
	}

	one := big.NewInt(1)
	upper := new(big.Int).Sub(dhPrime, one)
	if gA.Cmp(one) <= 0 || gA.Cmp(upper) >= 0 {
		return errors.New("g_a is out of range")
	}

	fingerprint := string(sha256sum(dhPrime.Bytes()))
	if _, ok := primeCache.Load(fingerprint); ok {
		return nil
	}
	if !dhPrime.ProbablyPrime(16) {
		return errors.New("dh_prime is not prime")
	}
	half := new(big.Int).Rsh(upper, 1)
	if !half.ProbablyPrime(16) {
		return errors.New("dh_prime is not a safe prime")
	}
	primeCache.Store(fingerprint, true)
	return nil
}

func sha256sum(p []byte) []byte {
	sum := sha256.Sum256(p)
	return sum[:]
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}

func bigEndian(v uint64) []byte {
	full := binary.BigEndian.AppendUint64(nil, v)
	for len(full) > 1 && full[0] == 0 {
		full = full[1:]
	}
	return full
}

type stream struct {
	w        io.Writer
	r        reader
	tr       transport
	tagFirst []byte

	deadline func(time.Time)

	// perStep bounds a single round trip whenever no call has claimed the
	// connection with a deadline of its own.
	perStep time.Duration
	until   time.Time

	sentAt  time.Time
	recvdAt time.Time
}

func (s *stream) firstRoundTrip() time.Duration {
	if s.sentAt.IsZero() || s.recvdAt.IsZero() {
		return 0
	}
	return s.recvdAt.Sub(s.sentAt)
}

func (s *stream) setDeadline(at time.Time) {
	s.until = at
	if s.deadline != nil {
		s.deadline(at)
	}
}

// step gives the next round trip its own deadline unless a call already set one.
func (s *stream) step() {
	if !s.until.IsZero() || s.perStep <= 0 || s.deadline == nil {
		return
	}
	s.deadline(time.Now().Add(s.perStep))
}

func (s *stream) sendUnencrypted(body []byte) error {
	message := make([]byte, 20+len(body))

	binary.LittleEndian.PutUint64(message[8:], messageID())
	binary.LittleEndian.PutUint32(message[16:], uint32(len(body)))
	copy(message[20:], body)
	return s.sendRaw(message)
}

func (s *stream) sendRaw(message []byte) error {
	s.step()

	packet, err := s.tr.encode(message)
	if err != nil {
		return err
	}
	if s.sentAt.IsZero() {
		s.sentAt = time.Now()
	}
	if s.tagFirst != nil {
		packet = append(append([]byte{}, s.tagFirst...), packet...)
		s.tagFirst = nil
	}
	_, err = s.w.Write(packet)
	return err
}

func (s *stream) recvUnencrypted() ([]byte, error) {
	packet, err := s.recvRaw()
	if err != nil {
		return nil, err
	}
	if len(packet) < 20 {
		return nil, fmt.Errorf("message is %d bytes, too short for a header", len(packet))
	}
	if !bytes.Equal(packet[:8], make([]byte, 8)) {
		return nil, fmt.Errorf("unexpected auth_key_id %x", packet[:8])
	}
	length := int(binary.LittleEndian.Uint32(packet[16:20]))
	if length < 4 || 20+length > len(packet) {
		return nil, fmt.Errorf("declared body length %d does not fit in %d bytes", length, len(packet)-20)
	}
	return packet[20 : 20+length], nil
}

func (s *stream) recvRaw() ([]byte, error) {
	packet, err := s.tr.decode(s.r)
	if err != nil {
		return nil, err
	}
	if s.recvdAt.IsZero() {
		s.recvdAt = time.Now()
	}
	return packet, nil
}
