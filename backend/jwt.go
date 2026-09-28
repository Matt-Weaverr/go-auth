package main

import (
	"encoding/base64"
	"encoding/json"
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

	signature, err := generateSignature([]byte(headerstring+"."+payloadjsonstring), CONFIG.Private_Key)
	if err != nil {
		return ""
	}
	senc := base64.RawURLEncoding.EncodeToString(signature)
	return headerstring + "." + payloadjsonstring + "." + senc
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

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Payload{}, false
	}

	if !verifySignature([]byte(parts[0]+"."+parts[1]), signature, CONFIG.Public_Key) {
		return Payload{}, false
	}

	return payload, true
}
