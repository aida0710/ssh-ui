.PHONY: generate test build fuzz e2e verify-generated integration integration-up integration-down integration-sshd-relax install uninstall update

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

# VERSION is what the built binary reports and what the update check compares
# against. A build with no tag says "dev", which is told there is a release and
# never told how far behind it is.
VERSION ?= $(shell git describe --tags --exact-match 2>/dev/null || echo dev)

build:
	npm run build --prefix web
	mkdir -p bin
	go build -trimpath -ldflags "-X main.version=$(VERSION)" -o bin/sshc ./cmd/sshc

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
	@printf '{"identities":[{"name":"sshc","credentials":[{"accessKey":"$(S3_KEY)","secretKey":"$(S3_SECRET)"}],"actions":["Admin","Read","Write","List","Tagging"]}]}' > .integration-s3.json
	docker rm -f sshc-s3 sshc-sshd >/dev/null 2>&1 || true
	docker run -d --name sshc-s3 -p 127.0.0.1:$(S3_PORT):8333 \
		-v "$(PWD)/.integration-s3.json:/etc/seaweedfs/s3.json:ro" $(S3_IMAGE) \
		server -s3 -s3.port=8333 -s3.config=/etc/seaweedfs/s3.json -dir=/data
	docker run -d --name sshc-sshd -p 127.0.0.1:$(SSHD_PORT):2222 \
		-e PASSWORD_ACCESS=true -e USER_NAME=$(SSH_USER) -e USER_PASSWORD=$(SSH_PASS) \
		$(SSHD_IMAGE)
	@echo "waiting for the containers to answer"
	@for i in $$(seq 1 60); do \
		curl -s -o /dev/null http://127.0.0.1:$(S3_PORT)/ && break; sleep 1; done
	@for i in $$(seq 1 60); do \
		(exec 3<>/dev/tcp/127.0.0.1/$(SSHD_PORT)) 2>/dev/null && break; sleep 1; done
	@$(MAKE) --no-print-directory integration-sshd-relax

# OpenSSH 10 turns PerSourcePenalties on by default, and this image ships 10.3.
# A penalty is charged per source address for a connection that disconnects
# without authenticating (every ssh-keyscan) and for one that fails to
# authenticate (two of these tests do so on purpose). The whole suite comes from
# one address within a few seconds, so the penalties accumulate past the
# threshold and sshd starts refusing connections part way through the run: the
# first CI run of this suite failed exactly that way, on the third test.
#
# A person connecting to their own server does not do this, so the penalty is
# measuring the harness rather than the product. It is turned off for the
# container only, and the result is checked rather than assumed: the directive
# goes into every sshd_config in the image, because which one this image starts
# sshd with is its business and not something worth hard-coding — the first
# attempt guessed the documented path and the image had moved it.
integration-sshd-relax:
	@docker exec sshc-sshd sh -c ' \
		found=$$(find /config /etc /defaults -name sshd_config 2>/dev/null); \
		if [ -z "$$found" ]; then \
			echo "this image has no sshd_config; the penalty cannot be turned off" >&2; \
			exit 1; \
		fi; \
		for configuration in $$found; do \
			grep -q "^PerSourcePenalties" "$$configuration" || \
				printf "\nPerSourcePenalties no\n" >> "$$configuration"; \
		done; \
		echo "PerSourcePenalties no ->" $$found'
	docker restart sshc-sshd
	@for i in $$(seq 1 60); do \
		ssh-keyscan -p $(SSHD_PORT) 127.0.0.1 2>/dev/null | grep -q . && break; sleep 1; done
	@# The check is the failure mode itself. Eight scans in a row from one
	@# address is more than the whole suite makes; with the penalty still on,
	@# sshd starts refusing part way through and this says so here, where the
	@# cause is obvious, instead of in the middle of a test.
	@for i in 1 2 3 4 5 6 7 8; do \
		ssh-keyscan -p $(SSHD_PORT) 127.0.0.1 2>/dev/null | grep -q . || { \
			echo "sshd refused connection $$i of 8 from one address: the per-source penalty is still on" >&2; \
			exit 1; \
		}; \
	done
	@echo "sshd accepts repeated connections from one address"

# The credentials the integration containers use are written at start and are
# fixtures, not secrets. The file is ignored rather than committed so its name
# never becomes a place somebody puts a real key.
integration-down:
	docker rm -f sshc-s3 sshc-sshd >/dev/null 2>&1 || true
	rm -f .integration-s3.json

# The bucket has to exist before the first PUT; the client deliberately has no
# CreateBucket, because the application never makes one either.
integration: build
	SSHC_TEST_S3_ENDPOINT=http://127.0.0.1:$(S3_PORT) \
	SSHC_TEST_S3_KEY=$(S3_KEY) \
	SSHC_TEST_S3_SECRET=$(S3_SECRET) \
	SSHC_TEST_S3_BUCKET=sshc-test \
	SSHC_TEST_SSH_ADDR=127.0.0.1:$(SSHD_PORT) \
	SSHC_TEST_SSH_USER=$(SSH_USER) \
	SSHC_TEST_SSH_PASSWORD=$(SSH_PASS) \
	go test ./internal/objectstore ./internal/remotesync ./internal/sshintegration -count=1 -v

# The binary goes to one stable path, and that matters more here than it
# usually does: SSH_ASKPASS and the Terminal launch both embed the absolute
# path of this binary at the moment they run, so a rebuild in another checkout
# or a moved repository silently breaks a stored-password connection.
#
# ~/.local/bin needs no sudo and no ownership of a system directory. If it is
# not on PATH this says so rather than installing somewhere nothing looks.
INSTALL_DIR ?= $(HOME)/.local/bin

install: build
	mkdir -p "$(INSTALL_DIR)"
	install -m 0755 bin/sshc "$(INSTALL_DIR)/sshc"
	@echo "installed $(INSTALL_DIR)/sshc"
	@case ":$$PATH:" in \
		*":$(INSTALL_DIR):"*) ;; \
		*) echo "note: $(INSTALL_DIR) is not on PATH; add it to run 'sshc <alias>' by name" ;; \
	esac

# For a source checkout, updating is fetching and installing again. It is not
# the same thing as the application's own update button: that one replaces a
# released binary for somebody who has no source to build from.
#
# --ff-only refuses rather than inventing a merge commit when the local branch
# has moved on, because "make update" should never be the thing that writes a
# commit nobody asked for.
update:
	git pull --ff-only
	$(MAKE) install

uninstall:
	rm -f "$(INSTALL_DIR)/sshc"
	@echo "removed $(INSTALL_DIR)/sshc"
