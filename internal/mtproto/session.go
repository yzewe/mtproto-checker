package mtproto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	ctorPing               = 0x7ABE77EC
	ctorPong               = 0x347773C5
	ctorMsgContainer       = 0x73F1F8DC
	ctorNewSessionCreated  = 0x9EC20908
	ctorBadServerSalt      = 0xEDAB447B
	ctorBadMsgNotification = 0xA7EBA1DB
)

type session struct {
	auth  *authKey
	id    []byte
	seqNo uint32
	salt  []byte
}

func newSession(auth *authKey) (*session, error) {
	id, err := randomBytes(8)
	if err != nil {
		return nil, err
	}
	return &session{auth: auth, id: id, salt: auth.salt}, nil
}

func (s *session) pingSeries(str *stream, count int, perPing time.Duration) (*PingStats, error) {
	if count < 1 {
		count = 1
	}

	samples := make([]time.Duration, 0, count)
	sent := 0
	for i := range count {
		if perPing > 0 {
			str.setDeadline(time.Now().Add(perPing))
		}
		sent++

		rtt, err := s.ping(str)
		if err != nil {
			if i == 0 {
				return nil, err
			}
			break
		}
		samples = append(samples, rtt)
	}
	return summarizeDurations(samples, sent), nil
}

func (s *session) ping(str *stream) (time.Duration, error) {
	pingID, err := randomBytes(8)
	if err != nil {
		return 0, err
	}
	body := &buf{}
	body.uint32(ctorPing)
	body.raw(pingID)

	packet, _, err := s.encrypt(body.done())
	if err != nil {
		return 0, err
	}

	started := time.Now()
	if err := str.sendRaw(packet); err != nil {
		return 0, err
	}

	for range 4 {
		response, err := str.recvRaw()
		if err != nil {
			return 0, fmt.Errorf("no pong: %w", err)
		}
		plain, err := s.decrypt(response)
		if err != nil {
			return 0, err
		}
		found, err := containsPong(plain, pingID)
		if err != nil {
			return 0, err
		}
		if found {
			return time.Since(started), nil
		}
	}
	return 0, errors.New("no pong among the server's replies")
}

func (s *session) encrypt(body []byte) ([]byte, uint64, error) {
	seqNo := s.seqNo*2 + 1
	s.seqNo++
	msgID := messageID()

	plain := &buf{}
	plain.raw(s.salt)
	plain.raw(s.id)
	plain.uint64(msgID)
	plain.uint32(seqNo)
	plain.uint32(uint32(len(body)))
	plain.raw(body)

	padding := 12 + (16-(plain.len()+12)%16)%16
	filler, err := randomBytes(padding)
	if err != nil {
		return nil, 0, err
	}
	plain.raw(filler)

	msgKey := messageKey(s.auth.key, plain.done(), 0)
	key, iv := messageKeys(s.auth.key, msgKey, 0)
	encrypted, err := igeEncrypt(plain.done(), key, iv)
	if err != nil {
		return nil, 0, err
	}
	return concat(s.auth.keyID, msgKey, encrypted), msgID, nil
}

func (s *session) decrypt(packet []byte) ([]byte, error) {
	if len(packet) < 24+16 {
		return nil, fmt.Errorf("encrypted message is only %d bytes", len(packet))
	}
	if !bytes.Equal(packet[:8], s.auth.keyID) {
		return nil, errors.New("reply is addressed to a different auth key")
	}
	msgKey := packet[8:24]

	key, iv := messageKeys(s.auth.key, msgKey, 8)
	plain, err := igeDecrypt(packet[24:], key, iv)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(messageKey(s.auth.key, plain, 8), msgKey) {
		return nil, errors.New("msg_key mismatch: the reply was tampered with")
	}

	if len(plain) < 32 {
		return nil, errors.New("decrypted message is too short")
	}
	length := int(binary.LittleEndian.Uint32(plain[28:32]))
	if length < 4 || 32+length > len(plain) {
		return nil, fmt.Errorf("declared body length %d does not fit", length)
	}
	return plain[32 : 32+length], nil
}

func messageKey(authKey, plain []byte, x int) []byte {
	sum := sha256.Sum256(concat(authKey[88+x:88+x+32], plain))
	return sum[8:24]
}

func messageKeys(authKey, msgKey []byte, x int) (key, iv []byte) {
	a := sha256.Sum256(concat(msgKey, authKey[x:x+36]))
	b := sha256.Sum256(concat(authKey[40+x:40+x+36], msgKey))
	key = concat(a[0:8], b[8:24], a[24:32])
	iv = concat(b[0:8], a[8:24], b[24:32])
	return key, iv
}

func containsPong(body, pingID []byte) (bool, error) {
	if len(body) < 4 {
		return false, errors.New("empty message body")
	}
	switch ctor := binary.LittleEndian.Uint32(body[:4]); ctor {
	case ctorPong:
		c := newCursor(body)
		c.uint32()
		c.uint64()
		got := c.take(8)
		if c.err != nil {
			return false, c.err
		}
		if !bytes.Equal(got, pingID) {
			return false, errors.New("pong carries a different ping_id")
		}
		return true, nil

	case ctorMsgContainer:
		c := newCursor(body)
		c.uint32()
		count := int(c.uint32())
		if count < 0 || count > 64 {
			return false, fmt.Errorf("implausible container size %d", count)
		}
		for range count {
			c.uint64()
			c.uint32()
			size := int(c.uint32())
			if size < 0 || size > len(body) {
				return false, errors.New("malformed container entry")
			}
			inner := c.take(size)
			if c.err != nil {
				return false, c.err
			}
			found, err := containsPong(inner, pingID)
			if err == nil && found {
				return true, nil
			}
		}
		return false, nil

	case ctorNewSessionCreated, ctorBadServerSalt, ctorBadMsgNotification:
		return false, nil

	case ctorRPCError:
		return false, errors.New("server answered with rpc_error")

	default:
		return false, nil
	}
}
