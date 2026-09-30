BINARY := bin/secrethawk

.PHONY: build test vet clean

build:
	mkdir -p bin
	go build -trimpath -o $(BINARY) ./cmd/secrethawk

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -rf bin
