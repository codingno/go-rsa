package gorsa

import (
	"encoding/pem"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateRSAKeyPair( t *testing.T) {
  privateKey, publicKey := GenerateRSAKeyPair(2048)
  assert.NotNil(t, privateKey, "private key not generated")
  assert.NotNil(t, publicKey, "public key not generated")
}

func TestEncryptDecrypt(t *testing.T) {
  privateKey, publicKey := GenerateRSAKeyPair(2048)
  data := "testing"
  label := "test"
  t.Run("encrypt empty label", func(t *testing.T) {
    _, err := EncryptWithPublicKey(data, publicKey)
    assert.NoError(t, err, "encrypt returned an error")
  })
  t.Run("encrypt with label", func(t *testing.T) {
    _, err := EncryptWithPublicKey(data, publicKey, label)
    assert.NoError(t, err, "encrypt returned an error")
  })
  t.Run("encrypt not string label", func(t *testing.T) {
    _, err := EncryptWithPublicKey(data, publicKey, 4)
    assert.Error(t, err, "encrypt not returned an error")
  })

  t.Run("decrypt empty label", func(t *testing.T) {
    encrypted, _ := EncryptWithPublicKey(data, publicKey)
    decrypted, err := DecryptWithPrivateKey(encrypted, privateKey)
    assert.NoError(t, err, "encrypt returned an error")
    assert.Equal(t, data, decrypted)
  })
  
  t.Run("decrypt with label", func(t *testing.T) {
    encrypted, _ := EncryptWithPublicKey(data, publicKey, label)
    decrypted, err := DecryptWithPrivateKey(encrypted, privateKey, label)
    assert.NoError(t, err, "encrypt not returned an error")
    assert.Equal(t, data, decrypted)
  })

  t.Run("decrypt not string label", func(t *testing.T) {
    encrypted, _ := EncryptWithPublicKey(data, publicKey, label)
    _, err := DecryptWithPrivateKey(encrypted, privateKey, 4)
    assert.Error(t, err, "encrypt not returned an error")
  })

  t.Run("decrypt wrong label", func(t *testing.T) {
    encrypted, _ := EncryptWithPublicKey(data, publicKey, label)
    _, err := DecryptWithPrivateKey(encrypted, privateKey, "wrong")
    assert.Error(t, err, "encrypt not returned an error")
  })
}

func TestReadFile(t *testing.T) {
  data, err := ReadFile("testing.file") 
  expected := []byte("testing\n")
  assert.NoError(t, err, "read file returned an error")
  assert.Equal(t, expected, data, "readed file not as expected")
}

func TestSavePEMFile(t *testing.T) {
  privateKey, publicKey := GenerateRSAKeyPair(2048)
  t.Run("save regular file", func(t *testing.T) {
    filename := "test.pem"
    keyType := "RSA PRIVATE KEY"
    keyBytes := []byte("testing")

    defer os.Remove(filename)

    err := SavePEMFile(filename, keyType, keyBytes)
    assert.NoError(t, err, "savePEMFile returned an error")

    pemData, _ := ReadFile(filename)

    pemBlock, _ := pem.Decode(pemData)
    assert.NotNil(t, pemBlock, "failed to decode PEM block")
    assert.Equal(t, pemBlock.Type, keyType, fmt.Sprintf("expected key type %q, got %q", keyType, pemBlock.Type))
    assert.Equal(t, pemBlock.Bytes, keyBytes, fmt.Sprintf("expected key bytes %q, got %q", keyBytes, pemBlock.Bytes))
  })

  t.Run("save privateKey file", func(t *testing.T) {
    defer os.Remove("private_key.pem")
    err := SavePrivateKeyToPEMFile(privateKey)
    assert.NoError(t, err, "SavePrivateKeyToPEMFile returned an error")
  })

  t.Run("save privateKey custom filename", func(t *testing.T) {
    filename := "private_name.pem"
    defer os.Remove(filename)
    err := SavePrivateKeyToPEMFile(privateKey, filename)
    assert.NoError(t, err, "SavePrivateKeyToPEMFile returned an error")
  })

  t.Run("save privateKey not string argument", func(t *testing.T) {
    err := SavePrivateKeyToPEMFile(privateKey, 4)
    assert.Error(t, err, "SavePrivateKeyToPEMFile should returned an error")
  })

  t.Run("save publicKey file", func(t *testing.T) {
    defer os.Remove("public_key.pem")
    err := SavePublicKeyToPEMFile(publicKey)
    assert.NoError(t, err, "SavePublicKeyToPEMFile returned an error")
  })

  t.Run("save privateKey custom filename", func(t *testing.T) {
    filename := "private_name.pem"
    defer os.Remove(filename)
    err := SavePublicKeyToPEMFile(publicKey, filename)
    assert.NoError(t, err, "SavePublicKeyToPEMFile returned an error")
  })

  t.Run("save privateKey not string argument", func(t *testing.T) {
    err := SavePublicKeyToPEMFile(publicKey, 4)
    assert.Error(t, err, "SavePrivateKeyToPEMFile should returned an error")
  })
}

func TestParseFromPEM(t *testing.T) {
  privateKey, publicKey := GenerateRSAKeyPair(2048)
  privateName, publicName := "private_key.pem", "public_key.pem"
  defer func() {
    os.Remove(privateName)
    os.Remove(publicName)
  }()
  SavePrivateKeyToPEMFile(privateKey)
  SavePublicKeyToPEMFile(publicKey)

  t.Run("parse privateKey from pem file", func(t *testing.T) {
    pemPrivate, err := ReadFile(privateName)
    assert.NoError(t, err, "ReadFile returned an error")
    privateKeyParsed, err := ParsePrivateKeyFromPEM(pemPrivate)
    assert.NoError(t, err, "ParsePrivateKeyFromPEM returned an error")
    assert.Equal(t, privateKey, privateKeyParsed, "Parsed private key not equal")
  })

  t.Run("parse publicKey from pem file", func(t *testing.T) {
    pemPublic, err := ReadFile(publicName)
    assert.NoError(t, err, "ReadFile returned an error")
    publicKeyParsed, err := ParsePublicKeyFromPEM(pemPublic)
    assert.NoError(t, err, "ParsePublicKeyFromPEM returned an error")
    assert.Equal(t, publicKey, publicKeyParsed, "Parsed public key not equal")
  })
}
