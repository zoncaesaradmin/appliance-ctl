SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

GO ?= go
VERSION ?= dev
LDFLAGS := -X main.version=$(VERSION)

BIN_DIR := bin
ZONCTL_BIN := $(BIN_DIR)/zonctl
VERIFY_LOG_DIR := $(CURDIR)/.run/logs
VERIFY_BUILD_LOG := $(VERIFY_LOG_DIR)/verify-build.log
VERIFY_BUILD_LINUX_LOG := $(VERIFY_LOG_DIR)/verify-build-linux.log
VERIFY_LINT_LOG := $(VERIFY_LOG_DIR)/verify-lint.log
VERIFY_VET_LINUX_LOG := $(VERIFY_LOG_DIR)/verify-vet-linux.log
VERIFY_TEST_LOG := $(VERIFY_LOG_DIR)/verify-test.log
VERIFY_RACE_LOG := $(VERIFY_LOG_DIR)/verify-race.log
VERIFY_SCHEMAS_LOG := $(VERIFY_LOG_DIR)/verify-schemas.log
VERIFY_MODTIDY_LOG := $(VERIFY_LOG_DIR)/verify-modtidy.log

.PHONY: build
build:
	mkdir -p $(BIN_DIR)
	$(GO) build -ldflags "$(LDFLAGS)" -o $(ZONCTL_BIN) ./cmd/zonctl

.PHONY: unit-test
unit-test:
	$(GO) test ./...

.PHONY: lint
lint:
	gofmt -l -s $$(find . -name '*.go' -not -path './.git/*') | tee /tmp/appliance-ctl-gofmt.out
	test ! -s /tmp/appliance-ctl-gofmt.out
	$(GO) vet ./...

.PHONY: verify-schemas
verify-schemas:
	$(GO) test ./internal/manifest/...

.PHONY: verify
verify:
	@set -e; \
	mkdir -p "$(VERIFY_LOG_DIR)"; \
	echo "verify stage: build (native)"; \
	if ! $(MAKE) --no-print-directory build >"$(VERIFY_BUILD_LOG)" 2>&1; then \
		echo "verify: build (native) failed; inspect $(VERIFY_BUILD_LOG)"; \
		exit 1; \
	fi; \
	echo "verify stage: build (native) passed"; \
	echo "verify stage: build (linux/amd64 cross-compile)"; \
	if ! GOOS=linux GOARCH=amd64 $(GO) build ./... >"$(VERIFY_BUILD_LINUX_LOG)" 2>&1; then \
		echo "verify: build (linux/amd64) failed; inspect $(VERIFY_BUILD_LINUX_LOG)"; \
		exit 1; \
	fi; \
	echo "verify stage: build (linux/amd64 cross-compile) passed"; \
	echo "verify stage: lint (gofmt + go vet, native)"; \
	if ! $(MAKE) --no-print-directory lint >"$(VERIFY_LINT_LOG)" 2>&1; then \
		echo "verify: lint failed; inspect $(VERIFY_LINT_LOG)"; \
		exit 1; \
	fi; \
	echo "verify stage: lint passed"; \
	echo "verify stage: go vet (linux/amd64 cross-compile)"; \
	if ! GOOS=linux GOARCH=amd64 $(GO) vet ./... >"$(VERIFY_VET_LINUX_LOG)" 2>&1; then \
		echo "verify: go vet (linux/amd64) failed; inspect $(VERIFY_VET_LINUX_LOG)"; \
		exit 1; \
	fi; \
	echo "verify stage: go vet (linux/amd64 cross-compile) passed"; \
	echo "verify stage: unit tests"; \
	if ! $(MAKE) --no-print-directory unit-test >"$(VERIFY_TEST_LOG)" 2>&1; then \
		echo "verify: unit tests failed; inspect $(VERIFY_TEST_LOG)"; \
		exit 1; \
	fi; \
	echo "verify stage: unit tests passed"; \
	echo "verify stage: race-detector tests"; \
	if ! $(GO) test ./... -race >"$(VERIFY_RACE_LOG)" 2>&1; then \
		echo "verify: race-detector tests failed; inspect $(VERIFY_RACE_LOG)"; \
		exit 1; \
	fi; \
	echo "verify stage: race-detector tests passed"; \
	echo "verify stage: schema/fixture validation"; \
	if ! $(MAKE) --no-print-directory verify-schemas >"$(VERIFY_SCHEMAS_LOG)" 2>&1; then \
		echo "verify: schema/fixture validation failed; inspect $(VERIFY_SCHEMAS_LOG)"; \
		exit 1; \
	fi; \
	echo "verify stage: schema/fixture validation passed"; \
	echo "verify stage: go mod tidy (no dependency drift)"; \
	cp go.mod "$(VERIFY_LOG_DIR)/go.mod.snapshot"; \
	cp go.sum "$(VERIFY_LOG_DIR)/go.sum.snapshot"; \
	if ! $(GO) mod tidy >"$(VERIFY_MODTIDY_LOG)" 2>&1; then \
		cp "$(VERIFY_LOG_DIR)/go.mod.snapshot" go.mod; \
		cp "$(VERIFY_LOG_DIR)/go.sum.snapshot" go.sum; \
		echo "verify: go mod tidy failed; inspect $(VERIFY_MODTIDY_LOG)"; \
		exit 1; \
	fi; \
	if cmp -s "$(VERIFY_LOG_DIR)/go.mod.snapshot" go.mod && cmp -s "$(VERIFY_LOG_DIR)/go.sum.snapshot" go.sum; then \
		echo "verify stage: go mod tidy passed (no drift)"; \
	else \
		cp "$(VERIFY_LOG_DIR)/go.mod.snapshot" go.mod; \
		cp "$(VERIFY_LOG_DIR)/go.sum.snapshot" go.sum; \
		echo "verify: go mod tidy found drift in go.mod/go.sum — run 'go mod tidy' locally, review the diff, and commit the result"; \
		exit 1; \
	fi; \
	echo "verify stage: clean"; \
	$(MAKE) --no-print-directory clean >/dev/null 2>&1; \
	echo "verify stage: clean passed"; \
	echo "verify: all mandatory checks passed"

.PHONY: assemble-bundle
assemble-bundle: build
	@if [ -z "$${BUNDLE_CONFIG:-}" ]; then \
		echo "assemble-bundle: set BUNDLE_CONFIG=/abs/path/to/bundle-assembly.json" >&2; \
		exit 2; \
	fi
	./$(ZONCTL_BIN) assemble-bundle --config "$${BUNDLE_CONFIG}"

.PHONY: verify-bundle
verify-bundle: build
	@if [ -z "$${BUNDLE_DIR:-}" ] || [ -z "$${PUBLIC_KEY:-}" ]; then \
		echo "verify-bundle: set BUNDLE_DIR=/abs/path/to/bundle and PUBLIC_KEY=/abs/path/to/release-signing.pub" >&2; \
		exit 2; \
	fi
	./$(ZONCTL_BIN) verify-bundle --bundle-dir "$${BUNDLE_DIR}" --public-key "$${PUBLIC_KEY}"

.PHONY: clean
clean:
	rm -rf $(BIN_DIR) $(VERIFY_LOG_DIR)
	find . -not -path './.git/*' \( \
		-name '*.test' -o \
		-name '*.out' -o \
		-name 'coverage.*' -o \
		-name '*.coverprofile' -o \
		-name 'profile.cov' \
	\) -delete
