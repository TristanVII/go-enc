package main

import (
	"crypto/rand"
	"fmt"
	"io"
)

const (
	KeySize   = 32
	NonceSize = 24
)

// GenerateKey creates a new random secret key
func generateKey() (*[KeySize]byte, error) {
	key := new([KeySize]byte)

	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		return nil, err
	}
	fmt.Printf("key: %v\n", key)
	return key, nil

}

// create a random nonce
func generateNonce() (*[NonceSize]byte, error) {

	nonce := new([NonceSize]byte)

	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return nil, err
	}
	fmt.Printf("nonce: %v\n", nonce)
	return nonce, nil
}
func main() {
	generateKey()
	generateNonce()
}
