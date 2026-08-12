package mtproto

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
)

const maxPacketLen = 1 << 20

type transport struct {
	name string
	tag  [4]byte

	directTag []byte
	encode    func(payload []byte) ([]byte, error)
	decode    func(r reader) ([]byte, error)
}

type reader interface {
	ReadFull(n int) ([]byte, error)
}

type plainReader struct{ r io.Reader }

func (p plainReader) ReadFull(n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(p.r, buf)
	return buf, err
}

var (
	intermediate = transport{
		name:      "intermediate",
		tag:       tagIntermediate,
		directTag: []byte{0xEE, 0xEE, 0xEE, 0xEE},
		encode:    encodeIntermediate,
		decode:    decodeIntermediate,
	}
	abridged = transport{
		name:      "abridged",
		tag:       tagAbridged,
		directTag: []byte{0xEF},
		encode:    encodeAbridged,
		decode:    decodeAbridged,
	}
	paddedIntermediate = transport{
		name:      "padded",
		tag:       tagPaddedIntermediate,
		directTag: []byte{0xDD, 0xDD, 0xDD, 0xDD},
		encode:    encodePaddedIntermediate,
		decode:    decodePaddedIntermediate,
	}
)

func encodeIntermediate(payload []byte) ([]byte, error) {
	out := make([]byte, 4+len(payload))
	binary.LittleEndian.PutUint32(out, uint32(len(payload)))
	copy(out[4:], payload)
	return out, nil
}

func decodeIntermediate(r reader) ([]byte, error) {
	head, err := r.ReadFull(4)
	if err != nil {
		return nil, err
	}
	length := int(binary.LittleEndian.Uint32(head))
	if length <= 0 || length > maxPacketLen {
		return nil, fmt.Errorf("invalid intermediate packet length: %d", length)
	}
	return r.ReadFull(length)
}

func encodePaddedIntermediate(payload []byte) ([]byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(4))
	if err != nil {
		return nil, err
	}
	padding := make([]byte, n.Int64())
	if _, err := rand.Read(padding); err != nil {
		return nil, err
	}
	return encodeIntermediate(append(append([]byte{}, payload...), padding...))
}

func decodePaddedIntermediate(r reader) ([]byte, error) {
	packet, err := decodeIntermediate(r)
	if err != nil {
		return nil, err
	}
	if extra := len(packet) % 4; extra != 0 {
		packet = packet[:len(packet)-extra]
	}
	return packet, nil
}

func encodeAbridged(payload []byte) ([]byte, error) {
	if len(payload)%4 != 0 {
		return nil, fmt.Errorf("abridged payload must be word-aligned, got %d bytes", len(payload))
	}
	words := len(payload) / 4
	if words < 127 {
		return append([]byte{byte(words)}, payload...), nil
	}
	head := []byte{0x7F, byte(words), byte(words >> 8), byte(words >> 16)}
	return append(head, payload...), nil
}

func decodeAbridged(r reader) ([]byte, error) {
	first, err := r.ReadFull(1)
	if err != nil {
		return nil, err
	}
	words := int(first[0])
	if words == 0x7F {
		ext, err := r.ReadFull(3)
		if err != nil {
			return nil, err
		}
		words = int(ext[0]) | int(ext[1])<<8 | int(ext[2])<<16
	}
	length := words * 4
	if length <= 0 || length > maxPacketLen {
		return nil, fmt.Errorf("invalid abridged packet length: %d", length)
	}
	return r.ReadFull(length)
}
