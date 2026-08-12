package mtproto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
)

var (
	tagIntermediate       = [4]byte{0xEE, 0xEE, 0xEE, 0xEE}
	tagAbridged           = [4]byte{0xEF, 0xEF, 0xEF, 0xEF}
	tagPaddedIntermediate = [4]byte{0xDD, 0xDD, 0xDD, 0xDD}
)

type obfConn struct {
	rw  io.ReadWriter
	enc cipher.Stream
	dec cipher.Stream
}

func newObfConn(rw io.ReadWriter, secretKey []byte, tag [4]byte, dcID int) (*obfConn, error) {
	header, err := obfuscationHeader(tag, dcID)
	if err != nil {
		return nil, err
	}

	encKey := sha256.Sum256(append(append([]byte{}, header[8:40]...), secretKey...))
	encIV := append([]byte{}, header[40:56]...)

	reversed := reverse(header)
	decKey := sha256.Sum256(append(append([]byte{}, reversed[8:40]...), secretKey...))
	decIV := reversed[40:56]

	encBlock, err := aes.NewCipher(encKey[:])
	if err != nil {
		return nil, err
	}
	decBlock, err := aes.NewCipher(decKey[:])
	if err != nil {
		return nil, err
	}

	c := &obfConn{
		rw:  rw,
		enc: cipher.NewCTR(encBlock, encIV),
		dec: cipher.NewCTR(decBlock, decIV),
	}

	encrypted := make([]byte, 64)
	c.enc.XORKeyStream(encrypted, header)
	copy(header[56:64], encrypted[56:64])

	if _, err := rw.Write(header); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *obfConn) Write(p []byte) (int, error) {
	buf := make([]byte, len(p))
	c.enc.XORKeyStream(buf, p)
	return c.rw.Write(buf)
}

func (c *obfConn) ReadFull(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(c.rw, buf); err != nil {
		return nil, err
	}
	c.dec.XORKeyStream(buf, buf)
	return buf, nil
}

func obfuscationHeader(tag [4]byte, dcID int) ([]byte, error) {
	forbidden := [][]byte{
		{0xDD, 0xDD, 0xDD, 0xDD},
		{0xEE, 0xEE, 0xEE, 0xEE},
		[]byte("POST"),
		[]byte("GET "),
		[]byte("HEAD"),
		{0x16, 0x03, 0x01, 0x02},
	}

	header := make([]byte, 64)
	for {
		if _, err := rand.Read(header); err != nil {
			return nil, err
		}
		if header[0] == 0xEF {
			continue
		}
		if binary.LittleEndian.Uint32(header[4:8]) == 0 {
			continue
		}
		if matchesAny(header[:4], forbidden) {
			continue
		}
		break
	}

	copy(header[56:60], tag[:])
	binary.LittleEndian.PutUint16(header[60:62], uint16(int16(dcID)))
	return header, nil
}

func matchesAny(prefix []byte, list [][]byte) bool {
	for _, candidate := range list {
		if string(prefix) == string(candidate) {
			return true
		}
	}
	return false
}

func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}
