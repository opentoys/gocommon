# gocommon
This repository relies only on standard libraries.

### crypto/aes
```go
var ecb128pkcs7 = aes.New([]byte("1234567890123456"))
ecb128pkcs7.Encrypt([]byte("msg"))
ecb128pkcs7.Bytes()
ecb128pkcs7.Error

var buf,e = aes.Encrypt([]byte("1234567890123456"), []byte("msg"))
```
### crypto/rsa 
### injects 
```go
package xxstore

type store struct{}

func init(){
	injects.Service.Register(&store{}, &injects.Config{Name:"store:mysql", Step: 10})
}
```
### otp
```go

var totp = otp.NewTOTP("secret", otp.TOTPWithPeriod(60))
var code, _ = totp.Generate()
var ok, _ = totp.Validate(code)
var url = totp.URL("Gcommon", "testid") // return url string. encode qrcode for scan 2FA.
```
### encoding/json 
```go
var buf = []byte(`{"a":1,"b":"hello","c":false,"d":{"a":1.234}}`)
var m,_ = json.Parse(buf) 
// map[a:1 b:hello c:false d:map[a:1.234]]
buf,_ = json.Stringify(m)
// []byte({"d":{"a":1.234},"a":1,"b":"hello","c":false})
```