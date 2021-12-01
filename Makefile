SHELL=/usr/bin/env bash


.PHONY: test
test:
	go test -v ./...