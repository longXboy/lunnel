export PATH := $(GOPATH)/bin:$(PATH)
export GO15VENDOREXPERIMENT := 1

build: lunelSer lunelCli

lunelCli:
	go build -o bin/client/lunnelCli ./cmd/lunnelCli
	@cp  ./cmd/lunnelCli/config-example.yml ./bin/client
	@cp  ./cmd/lunnelCli/cacert-example.pem ./bin/client

lunelSer:
	go build -o bin/server/lunnelSer ./cmd/lunnelSer
	@cp  ./cmd/lunnelSer/config-example.yml ./bin/server
	@cp  ./cmd/lunnelSer/example.crt ./bin/server
	@cp  ./cmd/lunnelSer/example.key ./bin/server

testAll:
	go test -v ./util/...
	go test -v ./transport/kcp/...
	go test -v ./crypto/...
	go test -v ./test/...