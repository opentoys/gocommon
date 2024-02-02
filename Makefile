.PHONY: test test-chinese

test-chinese:
	go test -coverprofile=test-chinese.out github.com/opentoys/gocommon/chinese/ && \
	go tool cover -html=test-chinese.out

test-chinese-holiday:
	go test -coverprofile=test-chinese-holiday.out github.com/opentoys/gocommon/chinese/holiday && \
	go tool cover -html=test-chinese-holiday.out

test-chinese-idcard:
	go test -coverprofile=test-chinese-idcard.out github.com/opentoys/gocommon/chinese/idcard/ && \
	go tool cover -html=test-chinese-idcard.out

test-encoding-json:
	go test -coverprofile=test-encoding-json.out github.com/opentoys/gocommon/encoding/json/ && \
	go tool cover -html=test-encoding-json.out

test-otp-totp:
	go test -coverprofile=test-otp-totp.out github.com/opentoys/gocommon/otp/ && \
	go tool cover -html=test-otp-totp.out


test-crypto-aes:
	go test -coverprofile=test-crypto-aes.out github.com/opentoys/gocommon/crypto/aes/ && \
	go tool cover -html=test-crypto-aes.out
	
test-crypto-rsa:
	go test -coverprofile=test-crypto-rsa.out github.com/opentoys/gocommon/crypto/rsa/ && \
	go tool cover -html=test-crypto-rsa.out

test:
	test-chinese && test-chinese-holiday && test-chinese-idcard