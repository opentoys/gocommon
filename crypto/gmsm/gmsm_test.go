package gmsm_test

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/opentoys/gocommon/crypto/gmsm"
)

var (
	key = []byte("1234567890123456")
	iv  = []byte("1234567890123456")

	msg = []byte("hello world sadkjaskjads")
)

func TestSM3(t *testing.T) {
	buf := gmsm.Sm3(msg)
	fmt.Println(hex.EncodeToString(buf))
	fmt.Println(base64.StdEncoding.EncodeToString(buf))
}

func TestCBC(t *testing.T) {
	sm4 := gmsm.NewSM4(
		key,
		gmsm.WithSM4IV(iv),
		gmsm.WithSM4Padding(gmsm.SM4_Padding_PKCS7),
	)

	buf, e := sm4.Encrypt(msg)
	if e != nil {
		t.Fatal(e)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(buf))
	msg, e := sm4.Decrypt(buf)
	if e != nil {
		t.Fatal(e)
	}
	fmt.Println(string(msg))
}

func TestGCM(t *testing.T) {
	sm4 := gmsm.NewSM4(key, gmsm.WithSM4IV(iv[:12]), gmsm.WithSM4Mode(gmsm.SM4_Mode_GCM))

	buf, e := sm4.Encrypt(msg)
	if e != nil {
		t.Fatal(e)
	}
	fmt.Printf("%x\n", buf)
	msg, e := sm4.Decrypt(buf)
	if e != nil {
		t.Fatal(e)
	}
	fmt.Println(string(msg))
}

func TestCCM(t *testing.T) {
	sm4 := gmsm.NewSM4(key, gmsm.WithSM4IV(iv[:12]), gmsm.WithSM4Mode(gmsm.SM4_Mode_CCM))

	buf, e := sm4.Encrypt(msg)
	if e != nil {
		t.Fatal(e)
	}
	fmt.Printf("%x\n", buf)
	msg, e := sm4.Decrypt(buf)
	if e != nil {
		t.Fatal(e)
	}
	fmt.Println(string(msg))
}

func TestCFB(t *testing.T) {
	sm4 := gmsm.NewSM4(key, gmsm.WithSM4IV(iv), gmsm.WithSM4Mode(gmsm.SM4_Mode_CFB))

	buf, e := sm4.Encrypt(msg)
	if e != nil {
		t.Fatal(e)
	}
	fmt.Printf("%x\n", buf)
	msg, e := sm4.Decrypt(buf)
	if e != nil {
		t.Fatal(e)
	}
	fmt.Println(string(msg))
}

func TestCTR(t *testing.T) {
	sm4 := gmsm.NewSM4(key, gmsm.WithSM4IV(iv), gmsm.WithSM4Mode(gmsm.SM4_Mode_CTR))

	buf, e := sm4.Encrypt(msg)
	if e != nil {
		t.Fatal(e)
	}
	fmt.Printf("%x\n", buf)
	msg, e := sm4.Decrypt(buf)
	if e != nil {
		t.Fatal(e)
	}
	fmt.Println(string(msg))
}

func TestECB(t *testing.T) {
	sm4 := gmsm.NewSM4(key, gmsm.WithSM4Mode(gmsm.SM4_Mode_ECB))

	buf, e := sm4.Encrypt(msg)
	if e != nil {
		t.Fatal(e)
	}
	fmt.Printf("%x\n", buf)
	msg, e := sm4.Decrypt(buf)
	if e != nil {
		t.Fatal(e)
	}
	fmt.Println(string(msg))
}

func TestOFB(t *testing.T) {
	var iv = make([]byte, 16)
	rand.Reader.Read(iv)
	fmt.Println(hex.EncodeToString(iv))
	sm4 := gmsm.NewSM4(key, gmsm.WithSM4IV(iv), gmsm.WithSM4Mode(gmsm.SM4_Mode_OFB))

	buf, e := sm4.Encrypt(msg)
	if e != nil {
		t.Fatal(e)
	}
	fmt.Printf("%x\n", buf)
	msg, e := sm4.Decrypt(buf)
	if e != nil {
		t.Fatal(e)
	}
	fmt.Println(string(msg))
}

func TestSM2Key(t *testing.T) {
	priv, e := gmsm.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}

	privkey := priv.D.Bytes()
	pubkey := elliptic.Marshal(priv.Curve, priv.X, priv.Y)

	priv2, e := gmsm.NewPrivateKey(privkey)
	if e != nil {
		t.Fatal(e)
	}

	if string(priv2.D.Bytes()) == string(privkey) {
		fmt.Println("ok")
	}

	pub2, e := gmsm.NewPublicKey(pubkey)
	if e != nil {
		t.Fatal(e)
	}

	if string(elliptic.Marshal(pub2, priv.X, priv.Y)) == string(pubkey) {
		fmt.Println("ok pub")
	}
}

func TestSm2(t *testing.T) {
	priv, e := gmsm.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}

	privkey := priv.D.Bytes()
	pubkey := elliptic.Marshal(priv.Curve, priv.X, priv.Y)
	fmt.Println(strings.ToUpper(hex.EncodeToString(privkey)))
	fmt.Println(strings.ToUpper(hex.EncodeToString(pubkey)))

	sm2 := gmsm.NewSM2(priv)
	buf, e := sm2.Encrypt(msg)
	if e != nil {
		t.Fatal(e)
	}

	fmt.Println(hex.EncodeToString(buf))
	msg, e := sm2.Decrypt(buf)
	if e != nil {
		t.Fatal(e)
	}
	fmt.Println(string(msg))

	sigend, e := sm2.Signature(buf)
	if e != nil {
		t.Fatal(e)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(sigend))

	fmt.Println("Verify: ", sm2.Verify(buf, sigend))
}
