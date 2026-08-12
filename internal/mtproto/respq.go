package mtproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"time"
)

const (
	ctorReqPQMulti = 0xBE7E8EF1
	ctorResPQ      = 0x05162463
)

func messageID() uint64 {
	now := time.Now()
	return uint64(now.Unix())<<32 | uint64(uint32(now.Nanosecond()/1000)<<2)
}

func quickCheck(s *stream) error {
	nonce, err := randomBytes(16)
	if err != nil {
		return err
	}
	if err := s.sendUnencrypted(reqPQMultiBody(nonce)); err != nil {
		return err
	}
	body, err := s.recvUnencrypted()
	if err != nil {
		return err
	}
	if len(body) < 20 {
		return errors.New("resPQ is too short")
	}
	if ctor := binary.LittleEndian.Uint32(body[:4]); ctor != ctorResPQ {
		return errors.New("answer is not a resPQ")
	}
	if !bytes.Equal(body[4:20], nonce) {
		return errors.New("resPQ nonce mismatch")
	}
	return nil
}
