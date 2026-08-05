.PHONY: generate test build fuzz e2e verify-generated

# FUZZTIME is per target. `make fuzz` is a campaign, not a single run, so the
# default is short enough to be part of an ordinary verification pass; raise it
# for a deliberate soak: `make fuzz FUZZTIME=10m`.
FUZZTIME ?= 30s

# Every fuzz target in the repository, as package:Target. Adding a target
# without adding it here fails TestMakefileFuzzTargetsCoverEveryFuzzFunction.
FUZZ_TARGETS = \
	internal/config:FuzzParseRendersOriginalBytes \
	internal/config:FuzzExpandIncludePattern \
	internal/effective:FuzzParseValues \
	internal/knownhosts:FuzzParseKnownHostsRoundTrip \
	internal/acceptance:FuzzAPIRequestBodies


generate:
	go generate ./internal/api
	npm run generate:api --prefix web

test:
	go test ./...
	go test -race ./...
	npm test --prefix web
	npm run typecheck --prefix web

fuzz:
	@set -e; for target in $(FUZZ_TARGETS); do \
		package="$${target%%:*}"; \
		name="$${target##*:}"; \
		echo "==> fuzz $$package $$name for $(FUZZTIME)"; \
		go test "./$$package" -run '^$$' -fuzz "^$$name$$" -fuzztime "$(FUZZTIME)"; \
	done

e2e: build
	npm run e2e --prefix web

# verify-generated regenerates the API models and fails if the committed ones
# differ. It is the proof that api/openapi.yaml is still the single source for
# both the Go models and the TypeScript types.
verify-generated: generate
	git diff --exit-code -- internal/api/models.gen.go web/src/api/schema.d.ts

build:
	npm run build --prefix web
	mkdir -p bin
	go build -trimpath -o bin/ssh-ui ./cmd/ssh-ui
