package main

import (
	"flag"
	"fmt"

	"github.com/kabili207/mesh-mqtt-server/pkg/auth"
)

func main() {
	length := flag.Int("length", 16, "Length of the password in bytes (will be hex encoded, so output is 2x this)")
	flag.Parse()

	// Generate random password
	password, err := auth.RandomHex(*length)
	if err != nil {
		fmt.Printf("Error generating password: %v\n", err)
		return
	}

	// Generate hash and salt
	hash, salt := auth.GenerateHashAndSalt(password)

	fmt.Printf("Password: %s\n", password)
	fmt.Printf("Salt:     %s\n", salt)
	fmt.Printf("Hash:     %s\n", hash)
}
