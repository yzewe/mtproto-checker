package mtproto

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
)

type buf struct{ b []byte }

func (b *buf) uint32(v uint32) {
	b.b = binary.LittleEndian.AppendUint32(b.b, v)
}

func (b *buf) uint64(v uint64) {
	b.b = binary.LittleEndian.AppendUint64(b.b, v)
}

func (b *buf) raw(p []byte) { b.b = append(b.b, p...) }

func (b *buf) bytes(p []byte) {
	if len(p) <= 253 {
		b.b = append(b.b, byte(len(p)))
	} else {
		b.b = append(b.b, 254, byte(len(p)), byte(len(p)>>8), byte(len(p)>>16))
	}
	b.b = append(b.b, p...)
	for len(b.b)%4 != 0 {
		b.b = append(b.b, 0)
	}
}

func (b *buf) len() int     { return len(b.b) }
func (b *buf) done() []byte { return b.b }

type cursor struct {
	b   []byte
	i   int
	err error
}

func newCursor(b []byte) *cursor { return &cursor{b: b} }

func (c *cursor) take(n int) []byte {
	if c.err != nil {
		return make([]byte, n)
	}
	if c.i+n > len(c.b) {
		c.err = io.ErrUnexpectedEOF
		return make([]byte, n)
	}
	out := c.b[c.i : c.i+n]
	c.i += n
	return out
}

func (c *cursor) uint32() uint32 { return binary.LittleEndian.Uint32(c.take(4)) }
func (c *cursor) uint64() uint64 { return binary.LittleEndian.Uint64(c.take(8)) }
func (c *cursor) int128() []byte { return c.take(16) }
func (c *cursor) int256() []byte { return c.take(32) }

func (c *cursor) bytes() []byte {
	first := c.take(1)
	length := int(first[0])
	if length == 254 {
		size := c.take(3)
		length = int(size[0]) | int(size[1])<<8 | int(size[2])<<16
	}
	out := c.take(length)
	for (c.i)%4 != 0 && c.err == nil {
		c.take(1)
	}
	return out
}

func (c *cursor) vectorLong() []uint64 {
	if ctor := c.uint32(); ctor != ctorVector && c.err == nil {
		c.err = fmt.Errorf("expected a vector, got 0x%08x", ctor)
		return nil
	}
	count := int(c.uint32())
	if count < 0 || count > 64 {
		if c.err == nil {
			c.err = fmt.Errorf("implausible vector length %d", count)
		}
		return nil
	}
	out := make([]uint64, 0, count)
	for range count {
		out = append(out, c.uint64())
	}
	return out
}

func (c *cursor) expect(want uint32, name string) {
	got := c.uint32()
	if c.err != nil || got == want {
		return
	}
	c.err = fmt.Errorf("expected %s (0x%08x), got 0x%08x%s", name, want, got, describeCtor(got))
}

func describeCtor(ctor uint32) string {
	switch ctor {
	case ctorServerDHParamsFail:
		return " (server_DH_params_fail)"
	case ctorDHGenRetry:
		return " (dh_gen_retry)"
	case ctorDHGenFail:
		return " (dh_gen_fail)"
	case ctorRPCError:
		return " (rpc_error)"
	}
	return ""
}

func bigFromBytes(p []byte) *big.Int { return new(big.Int).SetBytes(p) }

func padTo(v *big.Int, size int) []byte { return v.FillBytes(make([]byte, size)) }
