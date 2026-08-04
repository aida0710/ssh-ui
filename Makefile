.PHONY: generate test build fuzz

generate:
	go generate ./internal/api
	npm run generate:api --prefix web

test:
	go test ./...
	go test -race ./...
	npm test --prefix web
	npm run typecheck --prefix web

fuzz:
	go test ./internal/config -run '^$$' -fuzz FuzzParseRendersOriginalBytes -fuzztime 60s

build:
	npm run build --prefix web
	mkdir -p bin
	go build -trimpath -o bin/ssh-ui ./cmd/ssh-ui
