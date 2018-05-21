package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"

	log "github.com/sirupsen/logrus"
)

const (
	ivPad           = 12
	ivLen           = 4
	macLen          = 4
	hostOffset      = 1
	timestampOffset = 4
	kindOffset      = 0
)

// secret is used for computing mac of finalEphid and IV
var secret = []byte("the shared secret key here")

// managementServiceKey is the private used by the Management Service to compute
// the finalEphID from the plain text EphID
var managementServiceKey = "5368716e676520746869732070617373"

func computeMac(iv, finalEphID []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	message := append(iv, finalEphID...)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return expectedMAC[:macLen]
}

func verifyMac(message, msgMac []byte) bool {
	mac := hmac.New(sha256.New, secret)
	mac.Write(message)
	log.Info("msg Mac: ", msgMac)
	expectedMAC := mac.Sum(nil)
	return bytes.Equal(expectedMAC[:macLen], msgMac)
}

func decryptEphID(iv, msg []byte) *EphID {
	key, err := hex.DecodeString(managementServiceKey)
	if err != nil {
		panic(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	padIV := make([]byte, ivPad)
	iv = append(iv, padIV...)
	plaintext := make([]byte, aes.BlockSize)
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)
	ephID := &EphID{}
	ephID.kind[0] = ciphertext[aes.BlockSize] ^ msg[kindOffset]
	for i := range ephID.host {
		ephID.host[i] = msg[i+hostOffset] ^ ciphertext[aes.BlockSize+i+hostOffset]
	}
	for i := range ephID.timestamp {
		ephID.timestamp[i] = msg[i+timestampOffset] ^ ciphertext[aes.BlockSize+i+timestampOffset]
	}
	return ephID
}

func encryptEphID(ephID *EphID) ([]byte, []byte) {
	key, err := hex.DecodeString(managementServiceKey)
	if err != nil {
		panic(err)
	}
	plaintext := make([]byte, aes.BlockSize)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv[:ivLen]); err != nil {
		panic(err)
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)
	finalEphID := make([]byte, 8)
	finalEphID[kindOffset] = ephID.kind[0] ^ ciphertext[aes.BlockSize]
	for i, v := range ephID.host {
		finalEphID[i+hostOffset] = v ^ ciphertext[aes.BlockSize+hostOffset+i]
	}
	for i, v := range ephID.timestamp {
		finalEphID[i+timestampOffset] = v ^ ciphertext[aes.BlockSize+timestampOffset+i]
	}
	return ciphertext[:ivLen], finalEphID
}
