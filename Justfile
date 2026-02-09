default: test

build:
    go build -o mcp-firewall ./cmd/mcp-firewall

test:
    go test ./...

lint:
    go vet ./...

run config="config.yaml": build
    ./mcp-firewall -config {{config}}

echoserver:
    go build -o testdata/echoserver/echoserver ./testdata/echoserver

version v:
    go build -ldflags "-s -w -X main.version={{v}} -X main.commit=$(git rev-parse --short HEAD) -X main.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" -o mcp-firewall ./cmd/mcp-firewall

snapshot:
    goreleaser release --snapshot --clean
