.DEFAULT_GOAL := help

CARGO ?= cargo
NODE ?= node
NPM ?= npm
PROJECT_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
TARGET ?= .
MIN_RISK ?= 40
SCAN_FLAGS ?=
ARGS ?=

.PHONY: help fmt fmt-check clippy test build release run check ci \
	npm-ci npm-test npm-pack docs install-cargo-local install-npm-local \
	uninstall-npm scan self-scan

help: ## 顯示可用目標
	@awk 'BEGIN { FS = ":.*## " } /^[a-zA-Z0-9_.-]+:.*## / { printf "  %-24s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

fmt: ## 格式化所有 Rust 程式碼
	$(CARGO) fmt --all

fmt-check: ## 檢查 Rust 格式但不修改檔案
	$(CARGO) fmt --all -- --check

clippy: ## 執行所有 Rust target 的 Clippy 檢查
	$(CARGO) clippy --all-targets

test: ## 執行完整 Rust 測試
	$(CARGO) test

build: ## 建置 debug binary
	$(CARGO) build

release: ## 建置供安裝使用的 release binary
	$(CARGO) build --release

run: ## 執行開發版 CLI；可用 ARGS 傳入參數
	$(CARGO) run -- $(ARGS)

npm-ci: ## 依 lockfile 安裝 npm 相依套件且不執行 lifecycle scripts
	$(NPM) ci --ignore-scripts

npm-test: ## 執行 npm wrapper 測試
	$(NPM) test

npm-pack: ## 預覽 npm package 內容但不建立 tarball
	$(NPM) pack --dry-run

docs: ## 建置靜態網站資產
	$(NPM) run build:docs

check: fmt-check test npm-test ## 執行本機必要驗證

self-scan: ## 使用目前 Rust 原始碼掃描 TARGET
	$(CARGO) run --quiet -- --json --min-risk "$(MIN_RISK)" $(SCAN_FLAGS) "$(TARGET)"

ci: check self-scan ## 執行與 CI 對齊的檢查

install-cargo-local: release ## 以 cargo 全域安裝目前原始碼
	$(CARGO) install --path "$(PROJECT_ROOT)" --force

install-npm-local: release ## 以 npm 全域安裝目前尚未發佈的版本
	$(NODE) "$(PROJECT_ROOT)/npm/postinstall.cjs"
	$(NPM) install --global --ignore-scripts "$(PROJECT_ROOT)"

uninstall-npm: ## 移除全域 npm 版本
	$(NPM) uninstall --global leak-hunter

scan: ## 以 JSON 掃描 TARGET；可設定 MIN_RISK 與 SCAN_FLAGS
	$(CARGO) run --quiet -- --json --min-risk "$(MIN_RISK)" $(SCAN_FLAGS) "$(TARGET)"
