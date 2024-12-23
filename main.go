package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/secretbox"
)

const (
	KeySize   = 32
	NonceSize = 24
)

var (
	ErrEncrypt = errors.New("secret: encryption failed")
	ErrDecrypt = errors.New("secret: decryption failed")
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

func encrypt(key *[KeySize]byte, message []byte) ([]byte, error) {
	nonce, err := generateNonce()
	if err != nil {
		return nil, ErrEncrypt
	}

	out := make([]byte, len(nonce))
	copy(out, nonce[:])
	out = secretbox.Seal(out, message, nonce, key)
	return out, nil
	
}

// decrypt expects the encrypted message with the nonce
func decrypt(key *[KeySize]byte, message []byte) ([]byte, error) {
	if len(message) < (NonceSize + secretbox.Overhead) {
		return nil, ErrDecrypt
	}
	var nonce [NonceSize]byte
	copy(nonce[:], message[:NonceSize])
	out, ok := secretbox.Open(nil, message[NonceSize:], &nonce, key)
	if !ok {
		return nil, ErrDecrypt
	}
	return out, nil
}


func main() {
	message := []byte("Test123")
	key, err := generateKey()
	if err != nil {
		fmt.Println("Failed to generate key")
		return
	}
	encryptedMessage, err := encrypt(key, message)
	if err != nil {
		fmt.Println("Failed to encrypt")
		return
	}
	fmt.Printf("encryptedMessage: %s\n", string(encryptedMessage))
	decryptedMessage, err := decrypt(key, encryptedMessage)
	if err != nil {
		fmt.Println("Failed to decrypt")
		return
	}
	fmt.Printf("decryptedMessage: %s\n", string(decryptedMessage))
	if !bytes.Equal(message, decryptedMessage) {
		fmt.Println("Encrypted message and decrypted message do not match")
		return
	}
}
