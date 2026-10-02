BINARY := bin/secrethawk

.PHONY: build test vet fmt fuzz bench benchmark clean install

build:
	mkdir -p bin
	go build -trimpath -o $(BINARY) ./cmd/secrethawk

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w cmd internal pkg

fuzz:
	go test ./internal/scanner -run=^$$ -fuzz=FuzzShannonEntropy -fuzztime=30s

bench:
	go test ./internal/scanner -run=^$ -bench=. -benchmem

benchmark:
	go test ./internal/scanner -run=^$ -bench=. -benchmem -count=5

install:
	go install ./cmd/secrethawk

clean:
	rm -rf bin
