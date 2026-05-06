// Copyright ©2026 wantnotshould. All rights reserved.
// Author: wantnotshould
// Email: ur@xiaud.com

package gt

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"strings"
	"time"
	"unicode"
)

type Algorithm string

const (
	SHA1   Algorithm = "SHA1"
	SHA256 Algorithm = "SHA256"
	SHA512 Algorithm = "SHA512"
)

const (
	Digits6 = 6
	Digits8 = 8

	Timestep30s int64 = 30
	Timestep60s int64 = 60
)

type Config struct {
	Algorithm Algorithm
	Digits    int
	Timestep  int64
	Window    int
}

type Store interface {
	GetLastTimestamp(key string) (int64, error)
	SetLastTimestamp(key string, timestamp int64) error
}

type TOTP struct {
	config Config
	store  Store
}

var pow10 = []uint32{1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000}

func New(config Config, store Store) *TOTP {
	if config.Algorithm == "" {
		config.Algorithm = SHA1
	}
	if config.Digits <= 0 {
		config.Digits = Digits6
	}
	if config.Timestep <= 0 {
		config.Timestep = Timestep30s
	}
	return &TOTP{config: config, store: store}
}

func (v *TOTP) Generate(secret string) (string, error) {
	return v.GenerateAt(secret, time.Now())
}

func (v *TOTP) GenerateAt(secret string, at time.Time) (string, error) {
	return Generate(secret, at, v.config)
}

func (v *TOTP) Validate(key, secret, code string) (bool, error) {
	return v.ValidateAt(key, secret, code, time.Now())
}

func (v *TOTP) ValidateAt(key, secret, code string, at time.Time) (bool, error) {
	var lastUsedTS int64
	if v.store != nil {
		lastUsedTS, _ = v.store.GetLastTimestamp(key)
	}

	for i := -v.config.Window; i <= v.config.Window; i++ {
		t := at.Add(time.Duration(i) * time.Duration(v.config.Timestep) * time.Second)
		currentStepTS := (t.Unix() / v.config.Timestep) * v.config.Timestep

		if v.store != nil && currentStepTS <= lastUsedTS {
			continue
		}

		vCode, err := v.GenerateAt(secret, t)
		if err == nil && vCode == code {
			if v.store != nil {
				if err := v.store.SetLastTimestamp(key, currentStepTS); err != nil {
					return false, fmt.Errorf("replay store update failed: %w", err)
				}
			}
			return true, nil
		}
	}
	return false, nil
}

func Generate(secret string, t time.Time, config Config) (string, error) {
	if config.Timestep <= 0 || config.Digits < 1 || config.Digits >= len(pow10) {
		return "", errors.New("invalid config")
	}

	key, err := decodeBase32Secret(secret)
	if err != nil {
		return "", err
	}

	counter := uint64(t.Unix() / config.Timestep)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	h := hmac.New(config.Algorithm.hashFunc(), key)
	h.Write(buf[:])
	sum := h.Sum(nil)

	offset := sum[len(sum)-1] & 0xf
	binCode := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	code := binCode % pow10[config.Digits]
	return fmt.Sprintf("%0*d", config.Digits, code), nil
}

func (a Algorithm) hashFunc() func() hash.Hash {
	switch a {
	case SHA256:
		return sha256.New
	case SHA512:
		return sha512.New
	default:
		return sha1.New
	}
}

func decodeBase32Secret(secret string) ([]byte, error) {
	cleaned := strings.Map(func(r rune) rune {
		// remove spaces and '=' padding
		if unicode.IsSpace(r) || r == '=' {
			return -1
		}

		// convert lowercase letters to uppercase
		if 'a' <= r && r <= 'z' {
			return r - 32
		}

		// allow A-Z and 2-7 characters
		if (r >= 'A' && r <= 'Z') || (r >= '2' && r <= '7') {
			return r
		}

		// invalid character
		return 0
	}, secret)

	// check if any invalid characters are present
	if strings.ContainsRune(cleaned, 0) {
		return nil, errors.New("illegal base32 character")
	}

	// return error if the cleaned string is empty
	if cleaned == "" {
		return nil, errors.New("empty secret")
	}

	// if the cleaned string isn't a multiple of 8, pad it to fit Base32 encoding rules
	if mod := len(cleaned) % 8; mod != 0 {
		cleaned += strings.Repeat("=", 8-mod)
	}

	// decode the cleaned Base32 string and return the byte array
	return base32.StdEncoding.DecodeString(cleaned)
}
