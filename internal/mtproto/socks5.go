package mtproto

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/yzewe/mtproto-checker/internal/proxy"
)

func (c *Checker) probeSocks5(ctx context.Context, t *proxy.Target) (Outcome, error) {
	var problems []string
	var lastErr error
	for _, dc := range telegramDCs {
		conn, connectTime, err := c.dial(ctx, t.Addr())
		if err != nil {
			return Outcome{}, err
		}

		outcome, err := c.socks5Attempt(conn, t, dc.Addr, dc.ID, connectTime)
		conn.Close()
		if err == nil {
			return outcome, nil
		}
		lastErr = err

		var probeErr *Error

		if errors.As(err, &probeErr) && probeErr.Stage == StageHandshake {
			return Outcome{}, err
		}
		problems = append(problems, fmt.Sprintf("%s: %v", dc.Addr, err))
		if ctx.Err() != nil {
			return Outcome{}, fail(StageDial, ctx.Err())
		}
	}
	return Outcome{}, failAs(StageProtocol, KindOf(lastErr), errors.New(summarize(problems, 3)))
}

func (c *Checker) socks5Attempt(conn net.Conn, t *proxy.Target, dcAddr string, dcID int, connectTime time.Duration) (Outcome, error) {
	started := time.Now()
	if err := socks5Connect(conn, t.Username, t.Password, dcAddr); err != nil {
		return Outcome{}, err
	}
	handshake := time.Since(started)

	stages, err := c.directMTProto(conn, intermediate, dcID)
	if err != nil {
		return Outcome{}, err
	}
	return Outcome{
		Route: Route{
			Protocol:       "socks5",
			DC:             dcID,
			Transport:      intermediate.name,
			Via:            dcAddr,
			Depth:          c.depth(),
			ServerTimeSkew: stages.skew,
		},
		Timings: Timings{
			ConnectMS:   ms(connectTime),
			HandshakeMS: ms(handshake),
			RespQMS:     ms(stages.respq),
		},
		Ping:      stages.ping,
		Nearest:   stages.nearest,
		Config:    stages.config,
		Speed:     stages.speed,
		Stability: stages.stability,
	}, nil
}

func socks5Connect(conn net.Conn, username, password, dstAddr string) error {
	needsAuth := username != "" || password != ""

	greeting := []byte{0x05, 0x01, 0x00}
	if needsAuth {
		greeting[2] = 0x02
	}
	if _, err := conn.Write(greeting); err != nil {
		return fail(StageHandshake, err)
	}

	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fail(StageHandshake, fmt.Errorf("no SOCKS5 greeting reply: %w", err))
	}
	if reply[0] != 0x05 {
		return fail(StageHandshake, fmt.Errorf("not a SOCKS5 server (version %d)", reply[0]))
	}

	switch reply[1] {
	case 0x00:
	case 0x02:
		if err := socks5Auth(conn, username, password); err != nil {
			return err
		}
	case 0xFF:
		return failAs(StageHandshake, KindSocksAuth, errors.New("SOCKS5 server rejected all auth methods"))
	default:
		return fail(StageHandshake, fmt.Errorf("unsupported SOCKS5 auth method 0x%02x", reply[1]))
	}

	request, err := socks5ConnectRequest(dstAddr)
	if err != nil {
		return fail(StageProtocol, err)
	}
	if _, err := conn.Write(request); err != nil {
		return fail(StageProtocol, err)
	}
	return socks5ReadReply(conn)
}

func socks5Auth(conn net.Conn, username, password string) error {
	if len(username) > 255 || len(password) > 255 {
		return failAs(StageHandshake, KindSocksAuth, errors.New("SOCKS5 username or password is longer than 255 bytes"))
	}
	req := []byte{0x01, byte(len(username))}
	req = append(req, username...)
	req = append(req, byte(len(password)))
	req = append(req, password...)
	if _, err := conn.Write(req); err != nil {
		return fail(StageHandshake, err)
	}

	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fail(StageHandshake, fmt.Errorf("no SOCKS5 auth reply: %w", err))
	}
	if reply[0] != 0x01 || reply[1] != 0x00 {
		return failAs(StageHandshake, KindSocksAuth, errors.New("SOCKS5 credentials rejected"))
	}
	return nil
}

func socks5ConnectRequest(dstAddr string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(dstAddr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return nil, err
	}

	req := []byte{0x05, 0x01, 0x00}
	switch ip := net.ParseIP(host); {
	case ip == nil:
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	case ip.To4() != nil:
		req = append(req, 0x01)
		req = append(req, ip.To4()...)
	default:
		req = append(req, 0x04)
		req = append(req, ip.To16()...)
	}
	return binary.BigEndian.AppendUint16(req, uint16(port)), nil
}

func socks5ReadReply(conn net.Conn) error {
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return fail(StageProtocol, fmt.Errorf("no SOCKS5 CONNECT reply: %w", err))
	}
	if head[0] != 0x05 {
		return fail(StageProtocol, fmt.Errorf("bad SOCKS5 reply version %d", head[0]))
	}
	if head[1] != 0x00 {
		return failAs(StageProtocol, KindSocksRejected, fmt.Errorf("SOCKS5 CONNECT rejected: %s", socksReplyText(head[1])))
	}

	var skip int
	switch head[3] {
	case 0x01:
		skip = 4 + 2
	case 0x04:
		skip = 16 + 2
	case 0x03:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return fail(StageProtocol, err)
		}
		skip = int(length[0]) + 2
	default:
		return fail(StageProtocol, fmt.Errorf("unexpected SOCKS5 address type 0x%02x", head[3]))
	}
	if _, err := io.ReadFull(conn, make([]byte, skip)); err != nil {
		return fail(StageProtocol, err)
	}
	return nil
}

func socksReplyText(code byte) string {
	switch code {
	case 0x01:
		return "general failure"
	case 0x02:
		return "connection not allowed"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return fmt.Sprintf("code %d", code)
	}
}

func (c *Checker) directMTProto(conn net.Conn, tr transport, dcID int) (stageResults, error) {
	s := &stream{
		w:        conn,
		r:        plainReader{conn},
		tr:       tr,
		tagFirst: tr.directTag,
		deadline: deadlineSetter(conn),
		perStep:  c.Timeout,
	}
	if c.depth() == DepthFull {
		return c.fullHandshake(s, dcID)
	}

	var out stageResults
	if err := quickCheck(s); err != nil {
		return out, fail(StageProtocol, err)
	}
	out.respq = s.firstRoundTrip()
	return out, nil
}
