package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
)

var secret = []byte("the shared secret key here")

func computeMac(iv, finalEphID []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	message := append(iv, finalEphID...)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return expectedMAC[:4]
}

func getEphID(ephID *EphID) ([]byte, []byte) {
	key, err := hex.DecodeString("5368716e676520746869732070617373")
	if err != nil {
		panic(err)
	}
	plaintext := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, plaintext); err != nil {
		panic(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv[:4]); err != nil {
		panic(err)
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)
	finalEphID := make([]byte, 8)
	finalEphID[0] = ephID.kind[0] ^ ciphertext[aes.BlockSize]
	for i, v := range ephID.host {
		finalEphID[i+1] = v ^ ciphertext[aes.BlockSize+1+i]
	}
	for i, v := range ephID.timestamp {
		finalEphID[i+4] = v ^ ciphertext[aes.BlockSize+4+i]
	}
	return ciphertext[:4], finalEphID
}
