package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"crypto/x509"
	"io/ioutil"
	"encoding/pem"
	"time"
)

type Payload struct {
	Id int
	Name string
	Email string
	Exp int64
}


func loadRSAPublicKeyFromPEM(path string) ([]byte) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil
	}
	return data
}

func loadRSAPrivateKeyFromPEM(path string) (*rsa.PrivateKey) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return key
	}
	k2, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err2 != nil {
		return nil
	}
	priv, ok := k2.(*rsa.PrivateKey)
	if !ok {
		return nil
	}
	return priv
}

func generateJWT(id int, email string, name string) string {
	payload := Payload{
		Id:  id,
		Name: name,
		Email: email,
		Exp: time.Now().Add(15*time.Minute).Unix()}

		payloadjson,_ := json.Marshal(payload)
		payloadjsonstring := base64.RawURLEncoding.EncodeToString(payloadjson)
		priv := loadRSAPrivateKeyFromPEM("private_key.pem")
		if priv == nil {
			return ""
		}
		signature, err := generateSignature([]byte(payloadjsonstring), priv)
		if err != nil {
			return ""
		}
		senc := base64.RawURLEncoding.EncodeToString(signature)
		return payloadjsonstring + "." + senc
	}

func generateSignature(data []byte, priv *rsa.PrivateKey) ([]byte, error) {
	hash := sha256.Sum256(data);
	return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hash[:])
}



