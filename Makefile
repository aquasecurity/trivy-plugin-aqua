SHELL=/usr/bin/env bash


.PHONY: test
test:
	go test -v ./...

.PHONY: integration-test
integration-test:
	curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.27.0
	mkdir -p /home/runner/.trivy/plugins/aqua/
	go build -o /home/runner/.trivy/plugins/aqua/aqua cmd/aqua/main.go
	cp plugin.yaml /home/runner/.trivy/plugins/aqua/
	trivy config .
	trivy fs --debug --security-checks config,vuln,secret .
	docker pull alpine
	trivy --debug image alpine

.PHONY: update-plugin
update-plugin:
	@./scripts/update_plugin.sh

.PHONY: proto
proto:
	pushd pkg/proto && protoc --twirp_out=. --go_out=. ./buildsecurity.proto

.PHONY: build
build:
	docker run \
  --rm \
  -e GOARCH=amd64 \
  -e GOOS=linux \
  -w /build \
  -v `pwd`:/build \
  golang:1.18 \
  go build -o /build/bin/aqua cmd/aqua/main.go|| exit 1
