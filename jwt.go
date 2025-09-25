package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

var SECRET_KEY = []byte("nkmihbbilzkunhgcdgaohmlqdctbdpsnbdniiqzljzjpjehzuviqhxxgeznhiqzu")

type Payload struct {
	Id int
	Name string
	Email string
	Exp uint64
}
func generateJWT(id int, email string, name string) string {
	payload := Payload{
		Id:  id,
		Name: name,
		Email: email,
		Exp: uint64(time.Now().Add(15*time.Minute).Unix())}

		payloadjson,_ := json.Marshal(payload)
		payloadjsonstring := base64.RawURLEncoding.EncodeToString(payloadjson)
		return payloadjsonstring + "." + generateSignature(payloadjsonstring)
	}

func generateSignature(data string) string {
	hmac := hmac.New(sha256.New, SECRET_KEY)
	hmac.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(hmac.Sum(nil))
}

func verifyJWT(token string, refreshtoken string) (bool, string) {
	parts := strings.Split(token, ".")
	
	var payload Payload

	payloadbytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false, ""
	}

	if err = json.Unmarshal(payloadbytes, &payload); err != nil {
		return false, ""
	}
	if payload.Exp <= uint64(time.Now().Unix()) {
		p, err := read(payload.Id)
		if err != nil {
			return false, ""
		}
		if p.Refresh_Token_Expiration <= uint64(time.Now().Unix()) {
			return false, ""
		}
		if p.Refresh_Token != refreshtoken {
			return false, ""
		} else {
			return true, generateJWT(payload.Id, p.Email, p.Name)
		}
	}
	return true, ""
}

