package config

import "golang.org/x/oauth2"

type Configuration struct {
	ListenAddr    string
	SessionSecret string
	BaseURL       string
	OAuth         struct {
		Discord oauth2.Config
	}
	Database struct {
		User     string
		Password string
		Host     string
		DB       string
	}
}
