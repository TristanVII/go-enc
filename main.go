package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
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

type NaclEcryption struct {
	key *[KeySize]byte
}

// AES-GCM
type AESGCM struct {
	// The key length is 16 bytes for AES-128, 24 bytes for AES-192, or 32 bytes for AES-256
	key *[KeySize]byte
}

// GenerateKey creates a new random secret key
func generateKeyHelper() (*[KeySize]byte, error) {
	key := new([KeySize]byte)

	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		return nil, err
	}
	fmt.Printf("key: %v\n", key)
	return key, nil

}
// create a random nonce
func GenerateNonceHelper() (*[NonceSize]byte, error) {

	nonce := new([NonceSize]byte)

	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return nil, err
	}
	fmt.Printf("nonce: %v\n", nonce)
	return nonce, nil
}

// NACl encryption using "salt"
// NewNaclEncryption initializes a new instance of NaclEncryption with a generated key
func NewNaclEncryption(keyArg *[KeySize]byte) (*NaclEcryption, error) {
	key := keyArg
	if keyArg == nil {
		res, err := generateKeyHelper()
		if err != nil {
			return nil, err
		}
		key = res
	}
	return &NaclEcryption{key: key}, nil
}


func (n NaclEcryption) Encrypt(message []byte) ([]byte, error) {
	nonce, err := GenerateNonceHelper()
	if err != nil {
		return nil, ErrEncrypt
	}

	out := make([]byte, len(nonce))
	copy(out, nonce[:])
	out = secretbox.Seal(out, message, nonce, n.key)
	return out, nil

}

// decrypt expects the encrypted message with the nonce
func (n NaclEcryption) Decrypt(message []byte) ([]byte, error) {
	if len(message) < (NonceSize + secretbox.Overhead) {
		return nil, ErrDecrypt
	}
	var nonce [NonceSize]byte
	copy(nonce[:], message[:NonceSize])
	out, ok := secretbox.Open(nil, message[NonceSize:], &nonce, n.key)
	if !ok {
		return nil, ErrDecrypt
	}
	return out, nil
}

// Basic AES encryption without additional data 
func (a AESGCM) Encrypt(message []byte, additionalData []byte) ([]byte, error) {
	c, err := aes.NewCipher(a.key[:])
	if err != nil {
		return nil, ErrEncrypt
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, ErrEncrypt
	}
	nonce, err := GenerateNonceHelper()
	if err != nil {
		return nil, ErrEncrypt
	}
	// additionalData can be nil
	out := gcm.Seal(nonce[:], nonce[:], message, additionalData)
	return out, nil
}


func (a AESGCM) EncryptWithID(message []byte, sender uint32) ([]byte, error) {
	bufferForId := make([]byte, 4)
	binary.BigEndian.PutUint32(bufferForId, sender)
	return a.Encrypt(message, bufferForId)

}

func main() {
	// naclEncryption, _ := NewNaclEncryption(nil)
	// message := []byte("TestMessage123!")
	// encryptedMessage, _ := naclEncryption.Encrypt(message)
	// decryptedMessage, _ := naclEncryption.Decrypt(encryptedMessage)
	// fmt.Printf("Original Message: %s\nEncrypted Message: %s\nDecrypted Message: %s", string(message), string(encryptedMessage), string(decryptedMessage))
	Test1()
	Test2()
	Test3()
}
