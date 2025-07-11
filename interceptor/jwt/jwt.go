package jwt

import (
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

//openssl genrsa -out private.key 2048
//openssl rsa -in private.key -pubout -out public.key

func Generate(privateKey string, options jwt.Claims) (string, error) {

	claims := jwt.NewWithClaims(jwt.SigningMethodRS256, options)
	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privateKey))
	if err != nil {
		return "", fmt.Errorf("%s", "failed to parse private key: "+err.Error())
	}
	return claims.SignedString(key)
}

// Parse 分析token
func Parse(claims jwt.Claims, tokenString, publicKey string) (jwt.Claims, error) {

	key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(strings.Trim(publicKey, "")))
	if err != nil {
		return nil, fmt.Errorf("%s", "invalid public key: "+err.Error())
	}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {

		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}
	if token.Valid {
		return token.Claims, nil
	}
	return nil, fmt.Errorf("invalid token")
}
