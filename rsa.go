package gorsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
)

// Function to generate RSA key pair and save to files
func GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey) {
    privateKey, err := rsa.GenerateKey(rand.Reader, bits)
    if err != nil {
        fmt.Println(err)
        panic("rsa cannot generate key")
    }
    publicKey := &privateKey.PublicKey
    return privateKey, publicKey
}

// Function to save PEM file
func SavePEMFile(filename string, keyType string, bytes []byte) error {
    pemFile, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer pemFile.Close()

    var pemBlock = &pem.Block{
        Type:  keyType,
        Bytes: bytes,
    }

    return pem.Encode(pemFile, pemBlock)
}

func SavePrivateKeyToPEMFile(privateKey *rsa.PrivateKey, args ...any) error {

  filename := "private_key.pem"

  if len(args) > 0 {
    s, ok := args[0].(string)
    if !ok {
      return errors.New("second argument should be a string")
    }
    
    filename = s
  }

  privKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
  return SavePEMFile(filename, "RSA PRIVATE KEY", privKeyBytes)
}

func SavePublicKeyToPEMFile(publicKey *rsa.PublicKey, args ...any) error {

  filename := "public_key.pem"

  if len(args) > 0 {
    s, ok := args[0].(string)
    if !ok {
      return errors.New("second argument should be a string")
    }
    
    filename = s
  }

  pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
  if err != nil {
    return err
  }

  return SavePEMFile(filename, "RSA PUBLIC KEY", pubKeyBytes)
}

// Function to read file
func ReadFile(filename string) ([]byte, error) {
  file, err := os.Open(filename)
  if err != nil {
    return nil, err
  }
  defer file.Close()

  return io.ReadAll(file)
}

// Function to encrypt data with public key
func EncryptWithPublicKey(msg string, pubKey *rsa.PublicKey, args ...any) ([]byte, error) {
  label := []byte("")

  if len(args) > 0 {
    s, ok := args[0].(string)
    if !ok {
      return nil, errors.New("third argument should be a string")
    }
    label = []byte(s)
  }

  hash := sha256.New()
  ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pubKey, []byte(msg), label)
  if err != nil {
    return nil, err
  }
  return ciphertext, nil
}

// Function to decrypt data with private key
func DecryptWithPrivateKey(ciphertext []byte, privKey *rsa.PrivateKey, args ...any) (string, error) {
  label := []byte("")

  if len(args) > 0 {
    s, ok := args[0].(string)
    if !ok {
      return "", errors.New("third argument should be a string")
    }
    label = []byte(s)
  }

  hash := sha256.New()
  plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, privKey, ciphertext, label)
  if err != nil {
    return "", err
  }
  return string(plaintext), nil
}

// Function to sign data with private key
func SignWithPrivateKey(msg string, privKey *rsa.PrivateKey) ([]byte, error) {
    hash := sha256.New()
    hash.Write([]byte(msg))
    hashed := hash.Sum(nil)
    signature, err := rsa.SignPSS(rand.Reader, privKey, crypto.SHA256, hashed, nil)
    if err != nil {
        return nil, err
    }
    return signature, nil
}

// Function to verify data with public key
func VerifyWithPublicKey(signature []byte, msg string, pubKey *rsa.PublicKey) error {
    hash := sha256.New()
    hash.Write([]byte(msg))
    hashed := hash.Sum(nil)
    return rsa.VerifyPSS(pubKey, crypto.SHA256, hashed, signature, nil)
}
// Function to parse a PEM encoded private key
func ParsePrivateKeyFromPEM(pemData []byte) (*rsa.PrivateKey, error) {
    block, _ := pem.Decode(pemData)
    if block == nil || block.Type != "RSA PRIVATE KEY" {
        return nil, fmt.Errorf("failed to decode PEM block containing private key")
    }
    return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// Function to parse a PEM encoded public key
func ParsePublicKeyFromPEM(pemData []byte) (*rsa.PublicKey, error) {
    block, _ := pem.Decode(pemData)
    if block == nil || block.Type != "RSA PUBLIC KEY" {
        return nil, fmt.Errorf("failed to decode PEM block containing public key")
    }
    pub, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        return nil, err
    }
    return pub.(*rsa.PublicKey), nil
}

