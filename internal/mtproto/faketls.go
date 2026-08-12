package mtproto

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"
)

const tlsRecordLimit = 16384

type clientHello struct {
	bytes     []byte
	sessionID []byte
	random    []byte
}

func buildClientHello(sni string, secretKey []byte) (*clientHello, error) {
	serverName, err := encodeSNI(sni)
	if err != nil {
		return nil, err
	}

	grease, err := makeGrease(5)
	if err != nil {
		return nil, err
	}
	sessionID, err := randomBytes(32)
	if err != nil {
		return nil, err
	}
	keyShare, err := fakeX25519Key()
	if err != nil {
		return nil, err
	}

	b := &helloBuilder{}
	greasePair := func(i int) { b.put([]byte{grease[i], grease[i]}) }

	b.put([]byte{0x16, 0x03, 0x01})
	b.open()
	b.put([]byte{0x01, 0x00})
	b.open()
	b.put([]byte{0x03, 0x03})

	randomOffset := b.len()
	b.put(make([]byte, 32))

	b.put([]byte{0x20})
	b.put(sessionID)

	b.put([]byte{0x00, 0x20})
	greasePair(0)
	b.put([]byte{
		0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xC0, 0x2B, 0xC0, 0x2F, 0xC0, 0x2C, 0xC0, 0x30,
		0xCC, 0xA9, 0xCC, 0xA8, 0xC0, 0x13, 0xC0, 0x14, 0x00, 0x9C, 0x00, 0x9D, 0x00, 0x2F,
		0x00, 0x35,
	})
	b.put([]byte{0x01, 0x00})

	b.open()

	greasePair(1)
	b.put([]byte{0x00, 0x00})

	b.put([]byte{0x00, 0x00})
	b.open()
	b.open()
	b.put([]byte{0x00})
	b.open()
	b.put(serverName)
	b.close()
	b.close()
	b.close()

	b.put([]byte{0x00, 0x17, 0x00, 0x00})
	b.put([]byte{0xFF, 0x01, 0x00, 0x01, 0x00})
	b.put([]byte{0x00, 0x0A, 0x00, 0x0A, 0x00, 0x08})
	greasePair(2)
	b.put([]byte{0x00, 0x1D, 0x00, 0x17, 0x00, 0x18})
	b.put([]byte{0x00, 0x0B, 0x00, 0x02, 0x01, 0x00})
	b.put([]byte{0x00, 0x23, 0x00, 0x00})
	b.put([]byte{
		0x00, 0x10, 0x00, 0x0E, 0x00, 0x0C, 0x02, 'h', '2', 0x08,
		'h', 't', 't', 'p', '/', '1', '.', '1',
	})
	b.put([]byte{0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00})
	b.put([]byte{
		0x00, 0x0D, 0x00, 0x12, 0x00, 0x10, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01,
		0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01,
	})
	b.put([]byte{0x00, 0x12, 0x00, 0x00})
	b.put([]byte{0x00, 0x1B, 0x00, 0x03, 0x02, 0x00, 0x02})

	b.put([]byte{0x00, 0x33})
	b.open()
	b.open()
	greasePair(3)
	b.put([]byte{0x00, 0x01, 0x00})
	b.put([]byte{0x00, 0x1D, 0x00, 0x20})
	b.put(keyShare)
	b.close()
	b.close()

	b.put([]byte{0x00, 0x2D, 0x00, 0x02, 0x01, 0x01})
	b.put([]byte{0x00, 0x2B, 0x00, 0x07, 0x06})
	greasePair(4)
	b.put([]byte{0x03, 0x04, 0x03, 0x03})

	if pad := 517 - 4 - b.len(); pad > 0 {
		b.put([]byte{0x00, 0x15})
		b.open()
		b.put(make([]byte, pad))
		b.close()
	}

	b.close()
	b.close()
	b.close()

	digest := hmacSHA256(secretKey, b.bytes())
	clientRandom := make([]byte, 32)
	copy(clientRandom, digest[:28])
	now := uint32(time.Now().Unix())
	for i := range 4 {
		clientRandom[28+i] = byte(now>>(8*uint(i))) ^ digest[28+i]
	}
	b.overwrite(randomOffset, clientRandom)

	return &clientHello{bytes: b.bytes(), sessionID: sessionID, random: clientRandom}, nil
}

type helloBuilder struct {
	buf    []byte
	scopes []int
}

func (b *helloBuilder) put(p []byte)               { b.buf = append(b.buf, p...) }
func (b *helloBuilder) len() int                   { return len(b.buf) }
func (b *helloBuilder) bytes() []byte              { return b.buf }
func (b *helloBuilder) overwrite(at int, p []byte) { copy(b.buf[at:at+len(p)], p) }

func (b *helloBuilder) open() {
	b.scopes = append(b.scopes, len(b.buf))
	b.buf = append(b.buf, 0, 0)
}

func (b *helloBuilder) close() {
	start := b.scopes[len(b.scopes)-1]
	b.scopes = b.scopes[:len(b.scopes)-1]
	binary.BigEndian.PutUint16(b.buf[start:start+2], uint16(len(b.buf)-start-2))
}

func verifyServerHello(response, secretKey, sessionID, clientRandom []byte) error {
	records, err := splitTLSRecords(response)
	if err != nil {
		return err
	}
	if len(records) < 2 {
		return errors.New("FakeTLS ServerHello is incomplete")
	}
	if !bytes.HasPrefix(records[0], []byte{0x16, 0x03, 0x03}) {
		return errors.New("first record is not a ServerHello")
	}
	if records[len(records)-1][0] != 0x17 {
		return errors.New("FakeTLS handoff application-data record is missing")
	}
	for _, rec := range records[1:] {
		if rec[0] != 0x14 && rec[0] != 0x17 {
			return fmt.Errorf("unexpected TLS record type 0x%02x", rec[0])
		}
	}

	handshake := records[0][5:]
	if len(handshake) < 39 || handshake[0] != 0x02 {
		return errors.New("handshake payload is not a ServerHello")
	}
	idLen := int(handshake[38])
	if 39+idLen > len(handshake) {
		return errors.New("ServerHello session_id is truncated")
	}
	if !bytes.Equal(handshake[39:39+idLen], sessionID) {
		return errors.New("ServerHello session_id mismatch")
	}

	if len(response) < 43 {
		return errors.New("ServerHello is too short to carry a digest")
	}
	got := append([]byte{}, response[11:43]...)
	zeroed := append([]byte{}, response...)
	copy(zeroed[11:43], make([]byte, 32))
	want := hmacSHA256(secretKey, append(append([]byte{}, clientRandom...), zeroed...))
	if !hmac.Equal(got, want) {
		return errors.New("ServerHello HMAC mismatch (wrong secret or not an MTProto proxy)")
	}
	return nil
}

func readServerHello(r io.Reader) ([]byte, error) {
	var out []byte
	for {
		header := make([]byte, 5)
		if _, err := io.ReadFull(r, header); err != nil {
			return nil, err
		}
		if len(out) == 0 && header[0] != 0x16 {
			return nil, fmt.Errorf("unexpected first TLS record type 0x%02x", header[0])
		}
		payload := make([]byte, binary.BigEndian.Uint16(header[3:5]))
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, err
		}
		out = append(append(out, header...), payload...)

		switch header[0] {
		case 0x17:
			return out, nil
		case 0x16, 0x14:
		default:
			return nil, fmt.Errorf("unexpected TLS record type 0x%02x", header[0])
		}
	}
}

func splitTLSRecords(data []byte) ([][]byte, error) {
	var records [][]byte
	for offset := 0; offset < len(data); {
		if len(data)-offset < 5 {
			return nil, errors.New("incomplete TLS record header")
		}
		end := offset + 5 + int(binary.BigEndian.Uint16(data[offset+3:offset+5]))
		if end > len(data) {
			return nil, errors.New("incomplete TLS record payload")
		}
		records = append(records, data[offset:end])
		offset = end
	}
	return records, nil
}

type tlsConn struct {
	conn  io.ReadWriter
	buf   []byte
	first bool
}

func newTLSConn(conn io.ReadWriter) *tlsConn {
	return &tlsConn{conn: conn, first: true}
}

func (t *tlsConn) Write(p []byte) (int, error) {
	var out []byte
	if t.first {
		out = append(out, 0x14, 0x03, 0x03, 0x00, 0x01, 0x01)
		t.first = false
	}
	for start := 0; start < len(p); start += tlsRecordLimit {
		end := min(start+tlsRecordLimit, len(p))
		chunk := p[start:end]
		out = append(out, 0x17, 0x03, 0x03, byte(len(chunk)>>8), byte(len(chunk)))
		out = append(out, chunk...)
	}
	if _, err := t.conn.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (t *tlsConn) Read(p []byte) (int, error) {
	for len(t.buf) == 0 {
		header := make([]byte, 5)
		if _, err := io.ReadFull(t.conn, header); err != nil {
			return 0, err
		}
		payload := make([]byte, binary.BigEndian.Uint16(header[3:5]))
		if _, err := io.ReadFull(t.conn, payload); err != nil {
			return 0, err
		}
		switch header[0] {
		case 0x17:
			t.buf = payload
		case 0x14:
		default:
			return 0, fmt.Errorf("unexpected TLS record type 0x%02x", header[0])
		}
	}
	n := copy(p, t.buf)
	t.buf = t.buf[n:]
	return n, nil
}

func hmacSHA256(key, msg []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return mac.Sum(nil)
}

func fakeX25519Key() ([]byte, error) {
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	v, err := rand.Int(rand.Reader, p)
	if err != nil {
		return nil, err
	}
	v.Mod(v.Mul(v, v), p)

	be := v.FillBytes(make([]byte, 32))
	le := make([]byte, 32)
	for i := range be {
		le[i] = be[31-i]
	}
	return le, nil
}

func makeGrease(n int) ([]byte, error) {
	raw, err := randomBytes(n)
	if err != nil {
		return nil, err
	}
	grease := make([]byte, n)
	for i, b := range raw {
		value := (b & 0xF0) + 0x0A
		if i > 0 && grease[i-1] == value {
			value ^= 0x10
		}
		grease[i] = value
	}
	return grease, nil
}

func randomBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func encodeSNI(sni string) ([]byte, error) {
	name := strings.ToLower(strings.TrimSpace(sni))
	if name == "" {
		return nil, errors.New("empty FakeTLS domain")
	}
	for i := 0; i < len(name); i++ {
		if name[i] < 0x21 || name[i] > 0x7E {
			return nil, fmt.Errorf("FakeTLS domain is not ASCII: %q", sni)
		}
	}
	if len(name) > 255 {
		name = name[:255]
	}
	return []byte(name), nil
}
