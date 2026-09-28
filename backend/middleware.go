package main


import (
	"net/http"
	"strings"
	"encoding/base64"
	"time"
	"context"
)

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("auth_token")
		if err != nil || cookie.Value == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		result := strings.Split(cookie.Value, ".")
		if len(result) != 3 {
			http.Error(w, "Invalid token format", http.StatusUnauthorized)
			return
		}

		decSig, err := base64.RawURLEncoding.DecodeString(result[2])
		if err != nil {
			http.Error(w, "Invalid token signature", http.StatusUnauthorized)
			return
		}

		if !verifySignature([]byte(result[0]+"."+result[1]), []byte(decSig), []byte(CONFIG.Secret_Key)) {
			http.Error(w, "Invalid token signature", http.StatusUnauthorized)
			return
		}

		p, err := readProfile("id", result[0])
		if err != nil {
			http.Error(w, "Invalid User", http.StatusUnauthorized)
			return
		}

		if *p.Refresh_Token != result[1] {
			http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
			return
		}

		if p.Refresh_Token_Expiration == nil || *p.Refresh_Token_Expiration <= time.Now().Unix() {
			http.Error(w, "Refresh token expired", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "profile", p)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}