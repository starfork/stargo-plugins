package jwt

import (
	"fmt"
	"testing"
)

var privateKey = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC/BI2vRPyFCjOd
KbGlNLeX6pjx5ZL6/BPqKXbdbhr/+CDKNbon/wuCnLn4vQyVpwR7e6mZ6mNuK8hF
2RLtt3snGg2bahdP083zPiBaEORo9t/O7lhYhnWoAaCuaP0qQcgSjFOZJrj24sFs
4clZnDOo5T2F2MusV16wHR4m4dPlM/rh6R+yhWZzn81w8pT49l01feJJRQ8fA+dp
+WVzoq7WtpbLbI8WNTIzOghuX1bnffWu47pCKqIEXk+FpZnCmXhd7GsIz+h9NCQs
7RWwK0WR/Jirp0A0HXba82P6j4Mt4XKwWmQ8fsOQ/+L1pPHvx0h7AgGjRWnpFbK/
RxB6yQPDAgMBAAECggEABudCuZlcKPC38c+ecHKJyg877M4XtENk8tsBxTnj9ulA
Qh6T9jsU7uj8HZ2zdTsegdnzxLDAXCxv5fpU4Ut2w3CBGmNIqWVltYtCvw6KOrLl
XsSlY7mkSeiZJoR71cmf0e/JW6kXGTETvXwhe0AWa92xDgPKRJW5wdKjktMphch9
k5DDboxOHvlQWOv3s69Oj/7ib/oPVvR44XY5Nv6ISWxjNB9TlD7iuUrkpy6T+eA7
HUjeb9ScOy9B0cU8YzrBRsFCmum0+jDTrFlG+KhSIkxO3svNFgN4vlCv1Qhu1j4L
Rv8GF4QZedEIFCJvwD6VLSxg4TQRLH2cNUk5plgCUQKBgQDzVhe2Xv6Ej9h17+p3
rfgvNQXDCFaKHQRVb9VDhmHnJ4brsR2ekFfSdBlWfKadzWVRW1CYbNoqrYVqFqww
982NFO2yWZ1OmNA3UyFJIbsgwXkKRaiBLy7gSkzQLHN2hv/eKW8pIhxrLxtElp6T
h7iPC48Tes2zYlDSPdaEw4wp0QKBgQDI9W9FMS8nJGu0bpGxkcmtdKqowMwBkxGx
OIyT7ubSmxBBgJuasgV6GaLxmSy8S6GIcFPFLr/zEKWp0kx0r2+Bah6DfNmoqCdp
ghcZkwAHIdq1dcHMfvQ8HuYB65aUAn8O7eQ/9mzUlNq9e1dx80oSXKLcQtif7i0M
uUXb6FhlUwKBgQC4d6GOPUFRGQMNlQz4IUgt8VIm4eFI3mp0okzX3b3GUG61qhU8
KUyKXD0BFYnxws11+XWFt69D/ztOi1WJ4bFPrHftZoYcGThvWHO5TvrfAAxUPy5Y
kH5GxcypW6lER18c+egtFJDaqGFRg6U/TfoZZrfWGphpzrRaTUqcZumQoQKBgBDJ
yEDsifboKQNK1WsTNdkCzRsJ+EENa0X15nCZXbkscSA3wUgcJS79I0qxtDYKz3TZ
hXYMoMaKlnxocDCzU0ppdiEf9gMMATbkQk/FoxP1dRMBwm32EStQnYB9kPfOeZTi
tNXPHWppARkhS73eSEreaFCkWPqLaEIO3FIxx+i3AoGBAJpNCiWODGdXINzizsiF
mzbZmCZj3OGSDxkKSkGldrrnOeOR6wjtCPBSdKjVb9SuGPG8fQpZWkNhJBgjL6QR
11yDfn/jXuF7hqI5wsWJLPV8/pPJ+KzgpG9cd3zPZefsjMgz9YeiOyFE4VA37AAw
sQYhiv5Fhg7CBMbmAqeUP7M3
-----END PRIVATE KEY-----`

var publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvwSNr0T8hQoznSmxpTS3
l+qY8eWS+vwT6il23W4a//ggyjW6J/8Lgpy5+L0MlacEe3upmepjbivIRdkS7bd7
JxoNm2oXT9PN8z4gWhDkaPbfzu5YWIZ1qAGgrmj9KkHIEoxTmSa49uLBbOHJWZwz
qOU9hdjLrFdesB0eJuHT5TP64ekfsoVmc5/NcPKU+PZdNX3iSUUPHwPnafllc6Ku
1raWy2yPFjUyMzoIbl9W5331ruO6QiqiBF5PhaWZwpl4XexrCM/ofTQkLO0VsCtF
kfyYq6dANB122vNj+o+DLeFysFpkPH7DkP/i9aTx78dIewIBo0Vp6RWyv0cQeskD
wwIDAQAB
-----END PUBLIC KEY-----
`

type MyOptions struct {
	UID uint32 `json:"uid"` //鉴权用户的UID
	Options
}

// Option Option
type MyOption func(o *MyOptions)

// UID set uid
func UID(uid uint32) MyOption {
	return func(o *MyOptions) {
		o.UID = uid
	}
}

func NewMyOptions(opts ...MyOption) *MyOptions {
	options := &MyOptions{
		//UID:     11234523,
		Options: DefaultOptions(Issuer("sss")),
	}
	//options.Issuer = "dfsd"

	for _, o := range opts {
		o(options)
	}
	return options
}

func TestGenerate(t *testing.T) {

	opts := NewMyOptions(UID(1243))

	rs, err := Generate(privateKey, opts)
	fmt.Println(rs, err)

	c, err := Parse(opts, rs, publicKey)

	fmt.Println(c, err)
	if err == nil {
		c1 := c.(*MyOptions)
		fmt.Println(c1.UID)
	}
}
