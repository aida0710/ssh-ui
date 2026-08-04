.PHONY: generate test build

generate:
	go generate ./internal/api
	npm run generate:api --prefix web

test:
	go test ./...
	go test -race ./...
	npm test --prefix web
	npm run typecheck --prefix web

build:
	npm run build --prefix web
	mkdir -p bin
	go build -trimpath -o bin/ssh-ui ./cmd/ssh-ui
