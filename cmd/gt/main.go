// Copyright ©2026 cdme. All rights reserved.
// Author: https://cdme.cn
// Email: hi@cdme.cn

package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/wantnotshould/gt"
)

func main() {
	secret := flag.String("s", "", "Base32 secret (required)")
	digits := flag.Int("d", 6, "Number of digits (6 or 8)")
	step := flag.Int64("t", 30, "Timestep in seconds")
	algo := flag.String("a", "SHA1", "Algorithm (SHA1, SHA256, SHA512)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of gt:\n")
		fmt.Fprintf(os.Stderr, "  gt -s <secret> [-d 6] [-t 30] [-a SHA1]\n\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *secret == "" {
		fmt.Println("secret is required.")
		flag.Usage()
		os.Exit(1)
	}

	conf := gt.Config{
		Algorithm: gt.Algorithm(*algo),
		Digits:    *digits,
		Timestep:  *step,
	}

	code, err := gt.Generate(*secret, time.Now(), conf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error generating TOTP: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Code: %s\n", code)
}
