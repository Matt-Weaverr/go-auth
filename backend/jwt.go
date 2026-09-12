package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"strings"
	"time"
)

type Payload struct {
	Id    int
	Name  string
	Email string
	Exp   int64
}

type Pre_Auth struct {
	User_Id int   `json:"user_id"`
	Exp     int64 `json:"exp"`
}

func loadRSAPublicKeyFromPEM(path string) []byte {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil
	}
	return data
}

func loadRSAPrivateKeyFromPEM(path string) *rsa.PrivateKey {
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

func generateAccessJWT(id int, email string, name string) string {
	payload := Payload{
		Id:    id,
		Name:  name,
		Email: email,
		Exp:   time.Now().Add(15 * time.Minute).Unix(),
	}

	payloadjson, _ := json.Marshal(payload)
	payloadjsonstring := base64.RawURLEncoding.EncodeToString(payloadjson)
	headerjson, _ := json.Marshal(map[string]string{"alg": "RS256", "type": "JWT"})
	headerstring := base64.RawURLEncoding.EncodeToString(headerjson)
	priv := loadRSAPrivateKeyFromPEM("keys/private_key.pem")
	if priv == nil {
		return ""
	}
	signature, err := generateSignature([]byte(headerstring+"."+payloadjsonstring), priv)
	if err != nil {
		return ""
	}
	senc := base64.RawURLEncoding.EncodeToString(signature)
	return headerstring + "." + payloadjsonstring + "." + senc
}

func parseRSAPublicKey(data []byte) *rsa.PublicKey {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil
	}

	rsaKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil
	}

	return rsaKey
}

func verifyAccessJWT(token string) (Payload, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Payload{}, false
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Payload{}, false
	}

	var payload Payload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return Payload{}, false
	}

	if time.Now().Unix() > payload.Exp {
		return Payload{}, false
	}

	publicKeyData := loadRSAPublicKeyFromPEM("keys/public_key.pem")
	if publicKeyData == nil {
		return Payload{}, false
	}

	publicKey := parseRSAPublicKey(publicKeyData)
	if publicKey == nil {
		return Payload{}, false
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Payload{}, false
	}

	if !verifySignature([]byte(parts[0]+"."+parts[1]), signature, publicKey) {
		return Payload{}, false
	}

	return payload, true
}
