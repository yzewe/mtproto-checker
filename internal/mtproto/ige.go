package mtproto

import (
	"crypto/aes"
	"errors"
)

func igeEncrypt(data, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(data)%aes.BlockSize != 0 {
		return nil, errors.New("IGE input must be a multiple of 16 bytes")
	}
	if len(iv) != 2*aes.BlockSize {
		return nil, errors.New("IGE needs a 32-byte IV")
	}

	prevCipher := iv[:aes.BlockSize]
	prevPlain := iv[aes.BlockSize:]
	out := make([]byte, len(data))

	for i := 0; i < len(data); i += aes.BlockSize {
		plain := data[i : i+aes.BlockSize]
		chunk := xor(plain, prevCipher)
		block.Encrypt(chunk, chunk)
		copy(out[i:], xor(chunk, prevPlain))
		prevCipher = out[i : i+aes.BlockSize]
		prevPlain = plain
	}
	return out, nil
}

func igeDecrypt(data, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(data)%aes.BlockSize != 0 {
		return nil, errors.New("IGE input must be a multiple of 16 bytes")
	}
	if len(iv) != 2*aes.BlockSize {
		return nil, errors.New("IGE needs a 32-byte IV")
	}

	prevCipher := iv[:aes.BlockSize]
	prevPlain := iv[aes.BlockSize:]
	out := make([]byte, len(data))

	for i := 0; i < len(data); i += aes.BlockSize {
		cipherBlock := data[i : i+aes.BlockSize]
		chunk := xor(cipherBlock, prevPlain)
		block.Decrypt(chunk, chunk)
		copy(out[i:], xor(chunk, prevCipher))
		prevPlain = out[i : i+aes.BlockSize]
		prevCipher = cipherBlock
	}
	return out, nil
}

func xor(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}
