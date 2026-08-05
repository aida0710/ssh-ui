.PHONY: generate test build fuzz e2e verify-generated integration integration-up integration-down

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
	internal/acceptance:FuzzAPIRequestBodies \
	internal/remotesync:FuzzReadSnapshot


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

# The integration suite runs against a real S3 implementation and a real sshd,
# in containers. It answers two questions the hermetic suite cannot: what a
# real object store does with a conditional PUT, and whether the askpass helper
# actually authenticates against a server that asks for a password.
#
# Both suites skip when their environment variables are unset, so `make test`
# stays hermetic and offline.
S3_IMAGE   ?= chrislusf/seaweedfs:latest
SSHD_IMAGE ?= linuxserver/openssh-server:latest
S3_PORT    ?= 8333
SSHD_PORT  ?= 2222
S3_KEY     ?= SSHUITESTKEY
S3_SECRET  ?= sshuitestsecret
SSH_USER   ?= tester
SSH_PASS   ?= integration-only-password

integration-up:
	@printf '{"identities":[{"name":"ssh-ui","credentials":[{"accessKey":"$(S3_KEY)","secretKey":"$(S3_SECRET)"}],"actions":["Admin","Read","Write","List","Tagging"]}]}' > .integration-s3.json
	docker rm -f ssh-ui-s3 ssh-ui-sshd >/dev/null 2>&1 || true
	docker run -d --name ssh-ui-s3 -p 127.0.0.1:$(S3_PORT):8333 \
		-v "$(PWD)/.integration-s3.json:/etc/seaweedfs/s3.json:ro" $(S3_IMAGE) \
		server -s3 -s3.port=8333 -s3.config=/etc/seaweedfs/s3.json -dir=/data
	docker run -d --name ssh-ui-sshd -p 127.0.0.1:$(SSHD_PORT):2222 \
		-e PASSWORD_ACCESS=true -e USER_NAME=$(SSH_USER) -e USER_PASSWORD=$(SSH_PASS) \
		$(SSHD_IMAGE)
	@echo "waiting for the containers to answer"
	@for i in $$(seq 1 60); do \
		curl -s -o /dev/null http://127.0.0.1:$(S3_PORT)/ && break; sleep 1; done
	@for i in $$(seq 1 60); do \
		(exec 3<>/dev/tcp/127.0.0.1/$(SSHD_PORT)) 2>/dev/null && break; sleep 1; done

integration-down:
	docker rm -f ssh-ui-s3 ssh-ui-sshd >/dev/null 2>&1 || true
	rm -f .integration-s3.json

# The bucket has to exist before the first PUT; the client deliberately has no
# CreateBucket, because the application never makes one either.
integration: build
	SSH_UI_TEST_S3_ENDPOINT=http://127.0.0.1:$(S3_PORT) \
	SSH_UI_TEST_S3_KEY=$(S3_KEY) \
	SSH_UI_TEST_S3_SECRET=$(S3_SECRET) \
	SSH_UI_TEST_S3_BUCKET=ssh-ui-test \
	SSH_UI_TEST_SSH_ADDR=127.0.0.1:$(SSHD_PORT) \
	SSH_UI_TEST_SSH_USER=$(SSH_USER) \
	SSH_UI_TEST_SSH_PASSWORD=$(SSH_PASS) \
	go test ./internal/objectstore ./internal/remotesync ./internal/sshintegration -count=1 -v
