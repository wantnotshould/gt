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

	var targetSecret string
	var conf gt.Config
	var label string

	if *secretFlag != "" {
		targetSecret = *secretFlag
		conf = gt.Config{Algorithm: "SHA1", Digits: 6, Timestep: 30}
		label = "Manual"
	} else {
		path := expandPath(*configPath)
		accounts, err := loadConfig(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Config error: %v\n", err)
			os.Exit(1)
		}

		target := flag.Arg(0)
		if target == "" {
			printAccountList(accounts)
			return
		}

		acc, found := findAccount(accounts, target)
		if !found {
			fmt.Printf("Label '%s' not found.\n", target)
			os.Exit(1)
		}
		targetSecret = acc.Secret
		conf = gt.Config{
			Algorithm: gt.Algorithm(acc.Algorithm),
			Digits:    acc.Digits,
			Timestep:  acc.Period,
		}
		label = acc.Label
	}

	fmt.Printf("Account: %s\n", label)
	fmt.Println("Press Ctrl+C to stop.")
	fmt.Println("--------------------------")

	for {
		now := time.Now()
		code, err := gt.Generate(targetSecret, now, conf)
		if err != nil {
			fmt.Printf("\rError: %v", err)
			return
		}

		remaining := conf.Timestep - (now.Unix() % conf.Timestep)

		fmt.Printf("\rCode: \033[1;32m%s\033[0m  Expires in: %2ds ", code, remaining)

		time.Sleep(time.Second)
	}
}

func findAccount(accounts []Account, target string) (Account, bool) {
	for _, acc := range accounts {
		if strings.EqualFold(acc.Label, target) {
			return acc, true
		}
	}
	return Account{}, false
}

func printAccountList(accounts []Account) {
	fmt.Println("Usage: gt <label>")
	fmt.Println("Available labels:")
	for _, acc := range accounts {
		fmt.Printf(" - %s\n", acc.Label)
	}
}

func loadConfig(path string) ([]Account, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var accs []Account
	return accs, json.Unmarshal(data, &accs)
}

func expandPath(path string) string {
	if strings.HasPrefix(path, "~") {
		usr, _ := user.Current()
		path = filepath.Join(usr.HomeDir, path[1:])
	}
	return path
}
