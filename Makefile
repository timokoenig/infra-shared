.PHONY: test fmt

test:
	go vet ./... && go test ./... -count=1 -race

fmt:
	gofmt -w .
