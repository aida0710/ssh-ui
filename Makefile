.PHONY: generate test build fuzz e2e verify-generated integration integration-up integration-down integration-sshd-relax install uninstall update

# FUZZTIME は target ごとの時間である。`make fuzz` は単発の実行ではなくキャンペーン
# なので、既定値は通常の検証パスの一部として回せる程度に短くしてある。腰を据えて
# 走らせるときは引き上げること: `make fuzz FUZZTIME=10m`。
FUZZTIME ?= 30s

# リポジトリ内のすべての fuzz target を package:Target の形で列挙する。target を
# 追加してここに加え忘れると TestMakefileFuzzTargetsCoverEveryFuzzFunction が失敗する。
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

# verify-generated は API のモデルを再生成し、コミット済みのものと異なれば失敗する。
# api/openapi.yaml が、Go のモデルと TypeScript の型の両方にとって依然として唯一の
# 源であることの証明である。
verify-generated: generate
	git diff --exit-code -- internal/api/models.gen.go web/src/api/schema.d.ts

# VERSION は、ビルドされたバイナリが報告する値であり、更新確認が比較する対象でも
# ある。タグのないビルドは "dev" と名乗る。それにはリリースがあることは伝えるが、
# どれだけ遅れているかは決して伝えない。
VERSION ?= $(shell git describe --tags --exact-match 2>/dev/null || echo dev)

build:
	npm run build --prefix web
	mkdir -p bin
	go build -trimpath -ldflags "-X main.version=$(VERSION)" -o bin/sshc ./cmd/sshc

# 統合テストのスイートは、コンテナ内の本物の S3 実装と本物の sshd に対して走る。
# 密閉されたスイートには答えられない二つの問いに答える。本物のオブジェクトストアが
# 条件付き PUT に何をするのか、そして askpass ヘルパーが、パスワードを求めてくる
# サーバーに対して実際に認証を通せるのか、である。
#
# どちらのスイートも、環境変数が設定されていなければスキップする。したがって
# `make test` は密閉されたまま、オフラインのままである。
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

# OpenSSH 10 は PerSourcePenalties を既定で有効にし、このイメージは 10.3 を積んで
# いる。ペナルティは送信元アドレスごとに課され、認証せずに切断する接続（すべての
# ssh-keyscan がそれにあたる）と、認証に失敗する接続（ここのテストのうち二つが
# 意図的にそうする）が対象になる。スイート全体が数秒のうちにひとつのアドレスから
# 来るので、ペナルティは閾値を超えて積み上がり、sshd は実行の途中から接続を拒否し
# 始める。このスイートの初回 CI 実行は、まさにそうやって三つ目のテストで失敗した。
#
# 自分のサーバーへ接続する人がこんなことをするわけではないので、このペナルティが
# 測っているのは製品ではなくテストハーネスである。そこでコンテナに限って無効に
# し、その結果は仮定せずに確認する。ディレクティブはイメージ内のすべての
# sshd_config へ書き込む。このイメージが sshd をどれで起動するかはイメージ側の
# 事情であって、決め打ちする価値のあるものではないからだ — 最初の試みは文書化
# されたパスを当て推量し、イメージはそれを移動させていた。
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

# 統合テストのコンテナが使う資格情報は開始時に書き出されるもので、秘密ではなく
# フィクスチャである。このファイルをコミットせず無視するのは、その名前が、誰かが
# 本物の鍵を置く場所になってしまわないようにするためである。
integration-down:
	docker rm -f sshc-s3 sshc-sshd >/dev/null 2>&1 || true
	rm -f .integration-s3.json

# 最初の PUT より前にバケットが存在していなければならない。クライアントに意図的に
# CreateBucket がないのは、アプリケーションもバケットを作らないからである。
integration: build
	SSHC_TEST_S3_ENDPOINT=http://127.0.0.1:$(S3_PORT) \
	SSHC_TEST_S3_KEY=$(S3_KEY) \
	SSHC_TEST_S3_SECRET=$(S3_SECRET) \
	SSHC_TEST_S3_BUCKET=sshc-test \
	SSHC_TEST_SSH_ADDR=127.0.0.1:$(SSHD_PORT) \
	SSHC_TEST_SSH_USER=$(SSH_USER) \
	SSHC_TEST_SSH_PASSWORD=$(SSH_PASS) \
	go test ./internal/objectstore ./internal/remotesync ./internal/sshintegration -count=1 -v

# バイナリはひとつの安定したパスへ置く。これは通常より重要な意味を持つ。
# SSH_ASKPASS と Terminal の起動は、どちらも実行時にこのバイナリの絶対パスを
# その場で埋め込むので、別のチェックアウトでビルドし直したり、リポジトリを移動
# したりすると、保存済みパスワードでの接続が黙って壊れる。
#
# ~/.local/bin は sudo もシステムディレクトリの所有権も必要としない。PATH に
# 入っていない場合は、誰も見ない場所へインストールするのではなく、その旨を告げる。
INSTALL_DIR ?= $(HOME)/.local/bin

install: build
	mkdir -p "$(INSTALL_DIR)"
	install -m 0755 bin/sshc "$(INSTALL_DIR)/sshc"
	@echo "installed $(INSTALL_DIR)/sshc"
	@case ":$$PATH:" in \
		*":$(INSTALL_DIR):"*) ;; \
		*) echo "note: $(INSTALL_DIR) is not on PATH; add it to run 'sshc <alias>' by name" ;; \
	esac

# ソースからのチェックアウトにおける更新とは、取得し直してインストールし直すこと
# である。アプリケーション自身の更新ボタンとは別物だ。あちらは、ビルドするソースを
# 持たない人のためにリリース済みのバイナリを置き換えるものである。
#
# ローカルのブランチが進んでいる場合、--ff-only はマージコミットを勝手に作らずに
# 拒否する。「make update」が、誰も頼んでいないコミットを書くものであってはならない
# からだ。
update:
	git pull --ff-only
	$(MAKE) install

uninstall:
	rm -f "$(INSTALL_DIR)/sshc"
	@echo "removed $(INSTALL_DIR)/sshc"
