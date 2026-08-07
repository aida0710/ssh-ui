#!/bin/sh
set -eu

# 更新は、取得するリビジョンを確認できるよう通常の起動とは分けて行う。
make build
exec ./bin/sshc
