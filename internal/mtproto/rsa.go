package mtproto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sync"
)

const telegramPublicKeys = `
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAwVACPi9w23mF3tBkdZz+zwrzKOaaQdr01vAbU4E1pvkfj4sqDsm6
lyDONS789sVoD/xCS9Y0hkkC3gtL1tSfTlgCMOOul9lcixlEKzwKENj1Yz/s7daS
an9tqw3bfUV/nqgbhGX81v/+7RFAEd+RwFnK7a+XYl9sluzHRyVVaTTveB2GazTw
Efzk2DWgkBluml8OREmvfraX3bkHZJTKX4EQSjBbbdJ2ZXIsRrYOXfaA+xayEGB+
8hdlLmAjbCVfaigxX0CDqWeR1yFL9kwd9P0NsZRPsmoqVwMbMu7mStFai6aIhc3n
Slv8kg9qv1m6XHVQY3PnEw+QQtqSIXklHwIDAQAB
-----END RSA PUBLIC KEY-----
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g
5nKaMBwK/BIb9xUfg0Q29/2mgIR6Zr9krM7HjuIcCzFvDtr+L0GQjae9H0pRB2OO
62cECs5HKhT5DZ98K33vmWiLowc621dQuwKWSQKjWf50XYFw42h21P2KXUGyp2y/
+aEyZ+uVgLLQbRA1dEjSDZ2iGRy12Mk5gpYc397aYp438fsJoHIgJ2lgMv5h7WY9
t6N/byY9Nw9p21Og3AoXSL2q/2IJ1WRUhebgAdGVMlV1fkuOQoEzR7EdpqtQD9Cs
5+bfo3Nhmcyvk5ftB0WkJ9z6bNZ7yxrP8wIDAQAB
-----END RSA PUBLIC KEY-----
`

type publicKey struct {
	key         *rsa.PublicKey
	fingerprint uint64
}

var (
	loadKeysOnce sync.Once
	publicKeys   []publicKey
	loadKeysErr  error
)

func telegramKeys() ([]publicKey, error) {
	loadKeysOnce.Do(func() {
		rest := []byte(telegramPublicKeys)
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			key, err := x509.ParsePKCS1PublicKey(block.Bytes)
			if err != nil {
				loadKeysErr = fmt.Errorf("embedded Telegram key is unusable: %w", err)
				return
			}
			publicKeys = append(publicKeys, publicKey{key: key, fingerprint: keyFingerprint(key)})
		}
		if len(publicKeys) == 0 {
			loadKeysErr = errors.New("no embedded Telegram public keys")
		}
	})
	return publicKeys, loadKeysErr
}

func keyFingerprint(key *rsa.PublicKey) uint64 {
	var b buf
	b.bytes(key.N.Bytes())
	b.bytes(big.NewInt(int64(key.E)).Bytes())
	sum := sha1.Sum(b.done())
	return binary.LittleEndian.Uint64(sum[12:20])
}

func selectKey(fingerprints []uint64) (publicKey, error) {
	keys, err := telegramKeys()
	if err != nil {
		return publicKey{}, err
	}
	for _, fp := range fingerprints {
		for _, key := range keys {
			if key.fingerprint == fp {
				return key, nil
			}
		}
	}
	return publicKey{}, fmt.Errorf("server offered no known RSA key (fingerprints %x)", fingerprints)
}

func rsaPad(data []byte, key publicKey) ([]byte, error) {
	if len(data) > 144 {
		return nil, fmt.Errorf("RSA_PAD payload is %d bytes, limit is 144", len(data))
	}

	padding, err := randomBytes(192 - len(data))
	if err != nil {
		return nil, err
	}
	dataWithPadding := append(append([]byte{}, data...), padding...)
	dataPadReversed := reverse(dataWithPadding)

	for range 64 {
		tempKey, err := randomBytes(32)
		if err != nil {
			return nil, err
		}

		hash := sha256.Sum256(append(append([]byte{}, tempKey...), dataWithPadding...))
		dataWithHash := append(append([]byte{}, dataPadReversed...), hash[:]...)

		encrypted, err := igeEncrypt(dataWithHash, tempKey, make([]byte, 32))
		if err != nil {
			return nil, err
		}

		keyHash := sha256.Sum256(encrypted)
		keyAESEncrypted := append(xor(tempKey, keyHash[:]), encrypted...)

		value := bigFromBytes(keyAESEncrypted)
		if value.Cmp(key.key.N) >= 0 {
			continue
		}
		return padTo(new(big.Int).Exp(value, big.NewInt(int64(key.key.E)), key.key.N), 256), nil
	}
	return nil, errors.New("RSA_PAD could not produce a value below the modulus")
}

func randomBigInt(bits int) (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	return rand.Int(rand.Reader, max)
}
