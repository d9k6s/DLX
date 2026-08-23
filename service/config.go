/*
 * @Author: Vincent Yang
 * @Date: 2024-04-23 00:39:03
 * @LastEditors: Jason Lyu
 * @LastEditTime: 2025-04-08 13:45:00
 * @FilePath: /DLX/service/config.go
 * @Telegram: https://t.me/missuo
 * @GitHub: https://github.com/missuo
 *
 * Copyright © 2024 by Vincent, All Rights Reserved.
 */

package service

import (
	"flag"
	"fmt"
	"os"
)

type Config struct {
	IP              string
	Port            int
	Token           string
	DlSession       string
	DlRefreshToken  string
	DlTokenStore    string
	DlClientProfile string
	Proxy           string
}

func InitConfig() *Config {
	cfg := &Config{
		IP:              "0.0.0.0",
		Port:            1188,
		DlClientProfile: "ios",
	}

	// IP flag
	if ip, ok := os.LookupEnv("IP"); ok && ip != "" {
		cfg.IP = ip
	}
	flag.StringVar(&cfg.IP, "ip", cfg.IP, "set up the IP address to bind to")
	flag.StringVar(&cfg.IP, "i", cfg.IP, "set up the IP address to bind to")

	// Port flag
	if port, ok := os.LookupEnv("PORT"); ok && port != "" {
		fmt.Sscanf(port, "%d", &cfg.Port)
	}
	flag.IntVar(&cfg.Port, "port", cfg.Port, "set up the port to listen on")
	flag.IntVar(&cfg.Port, "p", cfg.Port, "set up the port to listen on")

	// DL Session flag
	flag.StringVar(&cfg.DlSession, "s", "", "set the DeepL Pro OAuth Bearer access token for /v1/translate endpoint")
	if cfg.DlSession == "" {
		if dlSession, ok := os.LookupEnv("DL_SESSION"); ok {
			cfg.DlSession = dlSession
		}
	}

	// DeepL OAuth refresh token. Environment-only so the long-lived secret is
	// not exposed through process arguments.
	if dlRefreshToken, ok := os.LookupEnv("DL_REFRESH_TOKEN"); ok {
		cfg.DlRefreshToken = dlRefreshToken
	}

	// Optional state file used to persist rotated OAuth tokens across restarts.
	if dlTokenStore, ok := os.LookupEnv("DL_TOKEN_STORE"); ok {
		cfg.DlTokenStore = dlTokenStore
	}

	// Translation transport identity. Keep iOS as the compatibility default;
	// Chrome is an experimental approximation of the official extension.
	if dlClientProfile, ok := os.LookupEnv("DL_CLIENT_PROFILE"); ok && dlClientProfile != "" {
		cfg.DlClientProfile = dlClientProfile
	}

	// Access token flag
	flag.StringVar(&cfg.Token, "token", "", "set the access token for /translate endpoint")
	if cfg.Token == "" {
		if token, ok := os.LookupEnv("TOKEN"); ok {
			cfg.Token = token
		}
	}

	// HTTP Proxy flag
	flag.StringVar(&cfg.Proxy, "proxy", "", "set the proxy URL for HTTP requests")
	if cfg.Proxy == "" {
		if proxy, ok := os.LookupEnv("PROXY"); ok {
			cfg.Proxy = proxy
		}
	}

	flag.Parse()
	return cfg
}
