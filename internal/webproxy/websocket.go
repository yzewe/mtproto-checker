package webproxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// A minimal RFC 6455 client: the carrier only needs binary messages in both
// directions, so there is no fragmentation to reassemble beyond continuation
// frames and no extension negotiation.

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xA
)

type wsCarrier struct {
	conn    net.Conn
	reader  *bufio.Reader
	timeout time.Duration
}

func dialWebSocket(ctx context.Context, c *Carrier) (*wsCarrier, error) {
	dialer := &net.Dialer{Timeout: c.timeout}
	raw, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(c.host, "443"))
	if err != nil {
		return nil, failure(StageSession, "%w", err)
	}

	conn := tls.Client(raw, &tls.Config{ServerName: c.host, NextProtos: []string{"http/1.1"}})
	if err := conn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, failure(StageSession, "TLS handshake: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(c.timeout))

	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		conn.Close()
		return nil, failure(StageSession, "%w", err)
	}
	nonce := base64.StdEncoding.EncodeToString(key)

	// A lane socket carries one stream and announces it in the subprotocol;
	// the multiplexed mode carries every stream over a single socket.
	subprotocol := "tproxy-v1." + c.session
	if c.mode == "websocket-lanes" {
		subprotocol = fmt.Sprintf("tproxy-lane-v1.%s.%d", c.session, streamID)
	}

	request := strings.Join([]string{
		"GET /api/v1/ws HTTP/1.1",
		"Host: " + c.host,
		"Upgrade: websocket",
		"Connection: Upgrade",
		"Sec-WebSocket-Key: " + nonce,
		"Sec-WebSocket-Version: 13",
		"Sec-WebSocket-Protocol: " + subprotocol,
		"Origin: " + c.origin,
		"User-Agent: " + userAgent,
		"", "",
	}, "\r\n")
	if _, err := conn.Write([]byte(request)); err != nil {
		conn.Close()
		return nil, failure(StageSession, "%w", err)
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		conn.Close()
		return nil, failure(StageSession, "reading the upgrade answer: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		return nil, failure(StageSession, "WebSocket upgrade answered %s", resp.Status)
	}
	if got := resp.Header.Get("Sec-WebSocket-Accept"); got != acceptKey(nonce) {
		conn.Close()
		return nil, failure(StageSession, "wrong Sec-WebSocket-Accept")
	}
	if got := resp.Header.Get("Sec-WebSocket-Protocol"); got != subprotocol {
		conn.Close()
		return nil, failure(StageSession, "relay echoed subprotocol %q", got)
	}

	return &wsCarrier{conn: conn, reader: reader, timeout: c.timeout}, nil
}

func acceptKey(nonce string) string {
	sum := sha1.Sum([]byte(nonce + wsGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func (w *wsCarrier) send(ctx context.Context, frames []byte) error {
	if len(frames) == 0 {
		return nil
	}
	w.applyDeadline(ctx)
	return w.writeMessage(opBinary, frames)
}

func (w *wsCarrier) receive(ctx context.Context) ([]byte, error) {
	w.applyDeadline(ctx)

	var message []byte
	for {
		opcode, payload, final, err := w.readFrame()
		if err != nil {
			return nil, err
		}

		switch opcode {
		case opPing:
			if err := w.writeMessage(opPong, payload); err != nil {
				return nil, err
			}
			continue
		case opPong:
			continue
		case opClose:
			return nil, io.EOF
		case opText:
			return nil, errors.New("relay sent a text message")
		}

		message = append(message, payload...)
		if final {
			return message, nil
		}
	}
}

func (w *wsCarrier) close() {
	_ = w.writeMessage(opClose, []byte{0x03, 0xE8})
	w.conn.Close()
}

func (w *wsCarrier) applyDeadline(ctx context.Context) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(w.timeout)
	}
	_ = w.conn.SetDeadline(deadline)
}

// writeMessage sends one masked client frame, as the protocol requires.
func (w *wsCarrier) writeMessage(opcode byte, payload []byte) error {
	header := []byte{0x80 | opcode}
	length := len(payload)
	switch {
	case length < 126:
		header = append(header, byte(0x80|length))
	case length <= 0xFFFF:
		header = append(header, 0x80|126, byte(length>>8), byte(length))
	default:
		header = append(header, 0x80|127)
		header = binary.BigEndian.AppendUint64(header, uint64(length))
	}

	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return err
	}
	header = append(header, mask[:]...)

	masked := make([]byte, length)
	for i := range payload {
		masked[i] = payload[i] ^ mask[i%4]
	}
	if _, err := w.conn.Write(append(header, masked...)); err != nil {
		return err
	}
	return nil
}

func (w *wsCarrier) readFrame() (opcode byte, payload []byte, final bool, err error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(w.reader, header); err != nil {
		return 0, nil, false, err
	}

	final = header[0]&0x80 != 0
	opcode = header[0] & 0x0F
	masked := header[1]&0x80 != 0
	length := uint64(header[1] & 0x7F)

	switch length {
	case 126:
		extended := make([]byte, 2)
		if _, err := io.ReadFull(w.reader, extended); err != nil {
			return 0, nil, false, err
		}
		length = uint64(binary.BigEndian.Uint16(extended))
	case 127:
		extended := make([]byte, 8)
		if _, err := io.ReadFull(w.reader, extended); err != nil {
			return 0, nil, false, err
		}
		length = binary.BigEndian.Uint64(extended)
	}
	if length > maxBodyBytes {
		return 0, nil, false, fmt.Errorf("WebSocket message of %d bytes is too large", length)
	}

	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(w.reader, mask[:]); err != nil {
			return 0, nil, false, err
		}
	}

	payload = make([]byte, length)
	if _, err := io.ReadFull(w.reader, payload); err != nil {
		return 0, nil, false, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return opcode, payload, final, nil
}
