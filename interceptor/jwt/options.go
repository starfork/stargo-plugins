package jwt

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Options struct {

	//jwtClaims jwt.StandardClaims
	jwt.RegisteredClaims
}

// Option Option
type Option func(o *Options)

// Expire expire
func Expire(expire int64) Option {
	return func(o *Options) {
		o.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Second * time.Duration(expire)))
		//o.ExpiresAt = expire
	}
}

// Issuer Issuer
func Issuer(issuer string) Option {
	return func(o *Options) {
		o.Issuer = issuer
	}
}

func Audience(aud ...string) Option {
	return func(o *Options) {
		o.Audience = append(o.Audience, aud...)
	}
}

// DefaultOptions default options
func DefaultOptions(opts ...Option) Options {
	nowTime := time.Now()
	expireTime := nowTime.Add(24 * 30 * time.Hour)

	options := Options{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expireTime),
			Issuer:    "stargo",
			//Audience:  jwt.ClaimStrings{"abc", "ef"},
		},
	}
	for _, o := range opts {
		o(&options)
	}

	return options
}
