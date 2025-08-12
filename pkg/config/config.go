package config

type Configuration struct {
	Database struct {
		User     string
		Password string
		Host     string
		DB       string
	}
}
