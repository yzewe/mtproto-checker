package mtproto

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	ctorRPCResult           = 0xF35C6D01
	ctorGzipPacked          = 0x3072CFA1
	ctorMsgsAck             = 0x62D6B459
	ctorInvokeWithLayer     = 0xDA9B0D0D
	ctorInitConnection      = 0xC1CD5EA9
	ctorHelpGetNearestDC    = 0x1FB33026
	ctorNearestDC           = 0x8E1A1775
	ctorHelpGetConfig       = 0xC4F9186B
	ctorConfig              = 0xCC1A241E
	ctorDCOption            = 0x18B7A10D
	ctorBoolTrue            = 0x997275B5
	ctorBoolFalse           = 0xBC799737
	ctorLangpackGetLangPack = 0xF2F2330A
	ctorLangPackDifference  = 0xF385C1F6
)

const apiLayer = 158

const maxRPCReplies = 16

type NearestDC struct {
	Country   string `json:"country"`
	ThisDC    int    `json:"this_dc"`
	NearestDC int    `json:"nearest_dc"`
}

type DCOption struct {
	ID   int    `json:"id"`
	Addr string `json:"addr"`
}

type ConfigInfo struct {
	ThisDC     int        `json:"this_dc"`
	TestMode   bool       `json:"test_mode"`
	Options    []DCOption `json:"dc_options,omitempty"`
	Unexpected []string   `json:"unexpected_dc_addresses,omitempty"`
	Parsed     bool       `json:"parsed"`
}

type SpeedStats struct {
	Bytes       int     `json:"bytes"`
	Seconds     float64 `json:"seconds"`
	KBPerSec    float64 `json:"kb_per_sec"`
	FirstByteMS float64 `json:"first_byte_ms,omitempty"`
}

type rpcError struct {
	Code    int
	Message string
}

func (e *rpcError) Error() string {
	return fmt.Sprintf("rpc_error %d %s", e.Code, e.Message)
}

// invoke sends an API query and waits for its rpc_result, unwrapping
// containers, gzip and salt corrections along the way.
func (s *session) invoke(str *stream, query []byte, timeout time.Duration) ([]byte, error) {
	// One deadline for the whole call: resetting it per reply would let a
	// chatty server stretch the call to many times the timeout.
	deadline := time.Now().Add(timeout)
	if timeout > 0 {
		str.setDeadline(deadline)
	}

	for retry := range 2 {
		packet, msgID, err := s.encrypt(query)
		if err != nil {
			return nil, err
		}
		if err := str.sendRaw(packet); err != nil {
			return nil, err
		}

		result, retryNeeded, err := s.awaitResult(str, msgID, deadline)
		if err != nil {
			return nil, err
		}
		if !retryNeeded {
			return result, nil
		}
		if retry == 1 {
			return nil, errors.New("server kept rejecting the salt")
		}
	}
	return nil, errors.New("no rpc_result")
}

func (s *session) awaitResult(str *stream, msgID uint64, deadline time.Time) (result []byte, retry bool, err error) {
	for range maxRPCReplies {
		if time.Now().After(deadline) {
			return nil, false, errors.New("timed out waiting for rpc_result")
		}
		raw, err := str.recvRaw()
		if err != nil {
			return nil, false, err
		}
		plain, err := s.decrypt(raw)
		if err != nil {
			return nil, false, err
		}

		result, retry, found, err := s.dispatch(plain, msgID)
		if err != nil {
			return nil, false, err
		}
		if retry {
			return nil, true, nil
		}
		if found {
			return result, false, nil
		}
	}
	return nil, false, errors.New("no rpc_result among the server's replies")
}

// dispatch walks one decrypted message looking for our answer.
func (s *session) dispatch(body []byte, msgID uint64) (result []byte, retry, found bool, err error) {
	if len(body) < 4 {
		return nil, false, false, errors.New("empty message body")
	}

	switch binary.LittleEndian.Uint32(body[:4]) {
	case ctorRPCResult:
		c := newCursor(body)
		c.uint32()
		answered := c.uint64()
		if c.err != nil {
			return nil, false, false, c.err
		}
		if answered != msgID {
			return nil, false, false, nil
		}
		payload, err := unwrap(body[c.i:])
		if err != nil {
			return nil, false, false, err
		}
		if len(payload) >= 4 && binary.LittleEndian.Uint32(payload[:4]) == ctorRPCError {
			return nil, false, false, parseRPCError(payload)
		}
		return payload, false, true, nil

	case ctorGzipPacked:
		payload, err := unwrap(body)
		if err != nil {
			return nil, false, false, err
		}
		return s.dispatch(payload, msgID)

	case ctorMsgContainer:
		c := newCursor(body)
		c.uint32()
		count := int(c.uint32())
		if count < 0 || count > 64 {
			return nil, false, false, fmt.Errorf("implausible container size %d", count)
		}
		for range count {
			c.uint64()
			c.uint32()
			size := int(c.uint32())
			if size < 0 || size > len(body) {
				return nil, false, false, errors.New("malformed container entry")
			}
			inner := c.take(size)
			if c.err != nil {
				return nil, false, false, c.err
			}
			result, retry, found, err := s.dispatch(inner, msgID)
			if err != nil || retry || found {
				return result, retry, found, err
			}
		}
		return nil, false, false, nil

	case ctorBadServerSalt:
		c := newCursor(body)
		c.uint32()
		c.uint64()
		c.uint32()
		c.uint32()
		salt := c.take(8)
		if c.err != nil {
			return nil, false, false, c.err
		}
		s.salt = append([]byte{}, salt...)
		return nil, true, false, nil

	case ctorNewSessionCreated:
		c := newCursor(body)
		c.uint32()
		c.uint64()
		c.uint64()
		salt := c.take(8)
		if c.err == nil {
			s.salt = append([]byte{}, salt...)
		}
		return nil, false, false, nil

	default:
		return nil, false, false, nil
	}
}

func parseRPCError(payload []byte) error {
	c := newCursor(payload)
	c.uint32()
	code := int(int32(c.uint32()))
	message := string(c.bytes())
	if c.err != nil {
		return c.err
	}
	return &rpcError{Code: code, Message: message}
}

// unwrap decompresses a gzip_packed object, or returns it untouched.
func unwrap(body []byte) ([]byte, error) {
	if len(body) < 4 || binary.LittleEndian.Uint32(body[:4]) != ctorGzipPacked {
		return body, nil
	}
	c := newCursor(body)
	c.uint32()
	packed := c.bytes()
	if c.err != nil {
		return nil, c.err
	}
	reader, err := gzip.NewReader(bytes.NewReader(packed))
	if err != nil {
		return nil, fmt.Errorf("gzip_packed: %w", err)
	}
	defer reader.Close()
	return io.ReadAll(io.LimitReader(reader, 16<<20))
}

// wrapQuery adds the invokeWithLayer(initConnection(...)) envelope every
// connection needs before its first API call.
func wrapQuery(apiID int, query []byte) []byte {
	inner := &buf{}
	inner.uint32(ctorInitConnection)
	inner.uint32(0)
	inner.uint32(uint32(apiID))
	inner.bytes([]byte("PC"))
	inner.bytes([]byte("Linux"))
	inner.bytes([]byte("1.0"))
	inner.bytes([]byte("en"))
	inner.bytes(nil)
	inner.bytes([]byte("en"))
	inner.raw(query)

	outer := &buf{}
	outer.uint32(ctorInvokeWithLayer)
	outer.uint32(apiLayer)
	outer.raw(inner.done())
	return outer.done()
}

func getNearestDC(s *session, str *stream, apiID int, timeout time.Duration) (*NearestDC, error) {
	query := &buf{}
	query.uint32(ctorHelpGetNearestDC)

	payload, err := s.invoke(str, wrapQuery(apiID, query.done()), timeout)
	if err != nil {
		return nil, err
	}

	c := newCursor(payload)
	c.expect(ctorNearestDC, "nearestDc")
	country := string(c.bytes())
	thisDC := int(int32(c.uint32()))
	nearest := int(int32(c.uint32()))
	if c.err != nil {
		return nil, c.err
	}
	return &NearestDC{Country: country, ThisDC: thisDC, NearestDC: nearest}, nil
}

func getConfig(s *session, str *stream, apiID int, timeout time.Duration) (*ConfigInfo, error) {
	query := &buf{}
	query.uint32(ctorHelpGetConfig)

	payload, err := s.invoke(str, wrapQuery(apiID, query.done()), timeout)
	if err != nil {
		return nil, err
	}
	return parseConfig(payload), nil
}

// parseConfig reads the fields before dc_options, which have been stable for
// many layers, and gives up quietly if the constructor is not the one we know.
func parseConfig(payload []byte) *ConfigInfo {
	info := &ConfigInfo{}
	if len(payload) < 4 || binary.LittleEndian.Uint32(payload[:4]) != ctorConfig {
		return info
	}

	c := newCursor(payload)
	c.uint32()
	c.uint32()
	c.uint32()
	c.uint32()
	testMode := c.uint32() == ctorBoolTrue
	thisDC := int(int32(c.uint32()))

	if c.uint32() != ctorVector {
		return info
	}
	count := int(c.uint32())
	if c.err != nil || count < 0 || count > 256 {
		return info
	}

	options := make([]DCOption, 0, count)
	for range count {
		if c.uint32() != ctorDCOption {
			return info
		}
		flags := c.uint32()
		id := int(int32(c.uint32()))
		address := string(c.bytes())
		port := int(int32(c.uint32()))
		if flags&(1<<10) != 0 {
			c.bytes()
		}
		if c.err != nil {
			return info
		}
		options = append(options, DCOption{ID: id, Addr: fmt.Sprintf("%s:%d", address, port)})
	}

	info.Parsed = true
	info.TestMode = testMode
	info.ThisDC = thisDC
	info.Options = options
	info.Unexpected = unexpectedAddresses(options)
	return info
}

// telegramNetworks are the prefixes Telegram publishes for its datacenters. An
// address outside them in help.getConfig means the proxy is redirecting
// traffic through hosts of its own.
var telegramNetworks = []string{
	"149.154.160.", "149.154.161.", "149.154.162.", "149.154.163.", "149.154.164.",
	"149.154.165.", "149.154.166.", "149.154.167.", "149.154.168.", "149.154.169.",
	"149.154.170.", "149.154.171.", "149.154.172.", "149.154.173.", "149.154.174.",
	"149.154.175.", "91.108.4.", "91.108.5.", "91.108.6.", "91.108.7.", "91.108.8.",
	"91.108.12.", "91.108.13.", "91.108.14.", "91.108.15.", "91.108.16.", "91.108.17.",
	"91.108.18.", "91.108.19.", "91.108.20.", "91.108.21.", "91.108.22.", "91.108.23.",
	"91.108.56.", "91.108.57.", "91.108.58.", "91.108.59.", "95.161.64.", "95.161.65.",
	"95.161.66.", "95.161.67.", "2001:067c:04e8", "2001:0b28:f23c", "2001:0b28:f23d",
	"2001:0b28:f23f", "2001:b28:f23d", "2001:b28:f23f", "2001:67c:4e8",
}

func unexpectedAddresses(options []DCOption) []string {
	var unexpected []string
	seen := map[string]bool{}
	for _, option := range options {
		host := option.Addr
		if i := bytes.LastIndexByte([]byte(host), ':'); i > 0 {
			host = host[:i]
		}
		if isTelegramAddress(host) || seen[host] {
			continue
		}
		seen[host] = true
		unexpected = append(unexpected, host)
	}
	return unexpected
}

func isTelegramAddress(host string) bool {
	for _, prefix := range telegramNetworks {
		if len(host) >= len(prefix) && host[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

// measureDownload pulls a language pack, the largest response Telegram serves
// without an account, and reports the throughput.
func measureDownload(s *session, str *stream, apiID int, timeout time.Duration) (*SpeedStats, error) {
	query := &buf{}
	query.uint32(ctorLangpackGetLangPack)
	query.bytes([]byte("android"))
	query.bytes([]byte("en"))

	started := time.Now()
	payload, err := s.invoke(str, wrapQuery(apiID, query.done()), timeout)
	if err != nil {
		return nil, err
	}
	elapsed := time.Since(started)

	if len(payload) >= 4 && binary.LittleEndian.Uint32(payload[:4]) != ctorLangPackDifference {
		return nil, fmt.Errorf("unexpected langpack answer 0x%08x", binary.LittleEndian.Uint32(payload[:4]))
	}

	seconds := elapsed.Seconds()
	stats := &SpeedStats{Bytes: len(payload), Seconds: round3(seconds)}
	if seconds > 0 {
		stats.KBPerSec = round1(float64(len(payload)) / 1024 / seconds)
	}
	return stats, nil
}

func round1(v float64) float64 { return float64(int64(v*10+0.5)) / 10 }
func round3(v float64) float64 { return float64(int64(v*1000+0.5)) / 1000 }
