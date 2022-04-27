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
	trivy fs --debug --security-checks config,vuln,secret .
	docker pull alpine
	trivy --debug image alpine

.PHONY: update-plugin
update-plugin:
	@./scripts/update_plugin.sh

proto:
	pushd pkg/proto && protoc --twirp_out=. --go_out=. ./buildsecurity.proto
