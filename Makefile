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

test:
	test-chinese && test-chinese-holiday && test-chinese-idcard