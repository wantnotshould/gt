// Copyright ©2026 cdme. All rights reserved.
// Author: https://cdme.cn
// Email: hi@cdme.cn

package gt

import (
	"testing"
	"time"
)

type MemStore struct {
	ts int64
}

func (s *MemStore) GetLastTimestamp(_ string) (int64, error)  { return s.ts, nil }
func (s *MemStore) SetLastTimestamp(_ string, ts int64) error { s.ts = ts; return nil }

func TestTOTPInstance(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	conf := Config{Algorithm: SHA1, Digits: 6, Timestep: 30, Window: 1}
	store := &MemStore{}

	totp := New(conf, store)

	code, err := totp.Generate(secret)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if len(code) != 6 {
		t.Errorf("Expected 6 digits, got %d", len(code))
	}

	key := "test:user:1"
	ok, err := totp.Validate(key, secret, code)
	if !ok || err != nil {
		t.Errorf("Validation failed: ok=%v, err=%v", ok, err)
	}

	ok, _ = totp.Validate(key, secret, code)
	if ok {
		t.Error("Replay attack should be blocked")
	}
}

func TestTOTPGenerateAt(t *testing.T) {
	totp := New(Config{Digits: 6}, nil)
	secret := "JBSWY3DPEHPK3PXP"

	fixedTime := time.Date(2026, 4, 20, 20, 0, 0, 0, time.UTC)
	code1, _ := totp.GenerateAt(secret, fixedTime)
	code2, _ := totp.GenerateAt(secret, fixedTime.Add(10*time.Second))

	if code1 != code2 {
		t.Error("Within 30s timestep, codes should be identical")
	}
}

func TestDecodeBase32(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"JBSW Y3DP EHPK 3PXP", false},
		{"jbswy3dpehpk3pxp", false},
		{"JBSWY3DPEHPK3PXP===", false},
		{"INVALID!!!", true},
	}

	for _, c := range cases {
		_, err := decodeBase32Secret(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("Input: %s, err: %v", c.in, err)
		}
	}
}
