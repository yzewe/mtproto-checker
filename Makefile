VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build vet fmt clean

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o mtproto-checker ./cmd/mtproto-checker

vet:
	go vet ./...

fmt:
	gofmt -l -w ./cmd ./internal

clean:
	rm -f mtproto-checker
