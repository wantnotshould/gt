// Copyright ©2026 cdme. All rights reserved.
// Author: https://cdme.cn
// Email: hi@cdme.cn

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/wantnotshould/gt"
)

type Account struct {
	Label     string `json:"label"`
	Secret    string `json:"secret"`
	Algorithm string `json:"algorithm"`
	Period    int64  `json:"period"`
	Digits    int    `json:"digits"`
	Issuer    string `json:"issuer"`
}

func main() {
	secretFlag := flag.String("s", "", "Directly provide secret")
	configPath := flag.String("c", "~/.gt.json", "Config file path")
	flag.Parse()

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of gt:\n")
		fmt.Fprintf(os.Stderr, "  gt -s <secret> [-d 6] [-t 30] [-a SHA1]\n\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *secretFlag != "" {
		generateAndPrint(gt.Config{Algorithm: "SHA1", Digits: 6, Timestep: 30}, *secretFlag, "Manual")
		return
	}

	path := expandPath(*configPath)
	accounts, err := loadConfig(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Config error: %v\n", err)
		os.Exit(1)
	}

	target := flag.Arg(0)
	if target == "" {
		fmt.Println("Available labels in config:")
		for _, acc := range accounts {
			fmt.Printf(" - %s (%s)\n", acc.Label, acc.Issuer)
		}
		return
	}

	for _, acc := range accounts {
		if strings.EqualFold(acc.Label, target) {
			conf := gt.Config{
				Algorithm: gt.Algorithm(acc.Algorithm),
				Digits:    acc.Digits,
				Timestep:  acc.Period,
			}
			generateAndPrint(conf, acc.Secret, acc.Label)
			return
		}
	}

	fmt.Printf("No configuration found for label: %s\n", target)
}

func generateAndPrint(conf gt.Config, secret string, label string) {
	code, err := gt.Generate(secret, time.Now(), conf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}
	fmt.Printf("[%s] Code: %s\n", label, code)
}

func loadConfig(path string) ([]Account, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var accounts []Account
	if err := json.Unmarshal(data, &accounts); err != nil {
		return nil, err
	}
	return accounts, nil
}

func expandPath(path string) string {
	if strings.HasPrefix(path, "~") {
		usr, _ := user.Current()
		path = filepath.Join(usr.HomeDir, path[1:])
	}
	return path
}
