package webproxy

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Shared frames: type:u8 | stream_id:u24 | payload_length:u32 | payload.
const (
	frameOpen    = 0x01
	frameData    = 0x02
	frameClose   = 0x03
	frameWindow  = 0x04
	framePing    = 0x05
	framePong    = 0x06
	frameHello   = 0x10
	frameWelcome = 0x11
	frameBye     = 0x1F
)

const (
	frameHeaderLen = 8
	maxPayload     = 1 << 20
)

type frame struct {
	kind    byte
	stream  uint32
	payload []byte
}

func encodeFrame(kind byte, stream uint32, payload []byte) []byte {
	out := make([]byte, frameHeaderLen+len(payload))
	out[0] = kind
	out[1] = byte(stream >> 16)
	out[2] = byte(stream >> 8)
	out[3] = byte(stream)
	binary.BigEndian.PutUint32(out[4:8], uint32(len(payload)))
	copy(out[frameHeaderLen:], payload)
	return out
}

func decodeFrames(body []byte) ([]frame, error) {
	var frames []frame
	for offset := 0; offset < len(body); {
		if len(body)-offset < frameHeaderLen {
			return nil, errors.New("truncated frame header")
		}
		head := body[offset : offset+frameHeaderLen]
		length := int(binary.BigEndian.Uint32(head[4:8]))
		if length > maxPayload {
			return nil, fmt.Errorf("frame payload of %d bytes exceeds the 1 MiB limit", length)
		}
		end := offset + frameHeaderLen + length
		if end > len(body) {
			return nil, errors.New("truncated frame payload")
		}
		frames = append(frames, frame{
			kind:    head[0],
			stream:  uint32(head[1])<<16 | uint32(head[2])<<8 | uint32(head[3]),
			payload: body[offset+frameHeaderLen : end],
		})
		offset = end
	}
	return frames, nil
}

func frameName(kind byte) string {
	switch kind {
	case frameOpen:
		return "OPEN"
	case frameData:
		return "DATA"
	case frameClose:
		return "CLOSE"
	case frameWindow:
		return "WINDOW"
	case framePing:
		return "PING"
	case framePong:
		return "PONG"
	case frameHello:
		return "HELLO"
	case frameWelcome:
		return "WELCOME"
	case frameBye:
		return "BYE"
	default:
		return fmt.Sprintf("0x%02x", kind)
	}
}
