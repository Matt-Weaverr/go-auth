package main

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"strings"
	"time"
)

const SECRET_KEY = "awsjkfhasjkfsehfsefhsekjfjsehfklsef"

type Payload struct {
	Id int
	Name string
	Email string
	Exp int64
}

type Pre_Auth struct {
	User_Id int `json:"user_id"`
	Exp int64 `json:"exp"`
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

func generateAccessJWT(id int, email string, name string) string {
	payload := Payload{
		Id:  id,
		Name: name,
		Email: email,
		Exp: time.Now().Add(15*time.Minute).Unix()}

		payloadjson,_ := json.Marshal(payload)
		payloadjsonstring := base64.RawURLEncoding.EncodeToString(payloadjson)
		headerjson, _ := json.Marshal(map[string]string{"alg": "RS256", "type": "JWT"})
		headerstring := base64.RawURLEncoding.EncodeToString(headerjson)
		priv := loadRSAPrivateKeyFromPEM("keys/private_key.pem")
		if priv == nil {
			return ""
		}
		signature, err := generateSignature([]byte(headerstring + "." + payloadjsonstring), priv)
		if err != nil {
			return ""
		}
		senc := base64.RawURLEncoding.EncodeToString(signature)
		return headerstring + "." + payloadjsonstring + "." + senc
	}

func generatePreAuthJWT(id int) string {
	data := Pre_Auth{
		User_Id: id,
		Exp: time.Now().Add(5*time.Minute).Unix(),
	}

	datajson, _ := json.Marshal(data)
	datastring := base64.RawURLEncoding.EncodeToString(datajson)

	h := hmac.New(sha256.New, []byte(SECRET_KEY))
	h.Write([]byte(datastring))
	sig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return datastring + "." + sig
}

func verifyPreAuthToken(token string) (bool, int) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return false, -1
	}

	sig := parts[1]
	data := parts[0]

	h := hmac.New(sha256.New, []byte(SECRET_KEY))
	h.Write([]byte(data))
	expectedsig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	if !hmac.Equal([]byte(sig), []byte(expectedsig)) {
		return false, -1
	}

	datadec, _ := base64.RawURLEncoding.DecodeString(data)
	var p Pre_Auth
	json.Unmarshal(datadec, &p)

	if time.Now().Unix() > p.Exp {
		return false, -1
	}

	return true, p.User_Id
}
	
func generateSignature(data []byte, priv *rsa.PrivateKey) ([]byte, error) {
	hash := sha256.Sum256(data);
	return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hash[:])
}



