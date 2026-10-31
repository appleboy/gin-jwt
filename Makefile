GO ?= go
TOOLS_MOD := -modfile=$(CURDIR)/go.tools.mod
LINT_CONFIG := $(CURDIR)/.golangci.yml
GO_PACKAGES := ./... ./_example/...
EXAMPLE_MODULES := _example/authorization _example/basic _example/oauth_sso _example/redis_store _example/token_generator

.PHONY: help format test lint clean coverage install-tools vet

# Default target
help:
	@echo "gin-jwt - Available Commands:"
	@echo ""
	@echo "  make format        - Format Go code using golangci-lint fmt"
	@echo "  make test          - Run tests with coverage"
	@echo "  make lint          - Run golangci-lint"
	@echo "  make vet           - Run go vet"
	@echo "  make coverage      - Generate and display test coverage"
	@echo "  make clean         - Clean test cache and coverage files"
	@echo "  make install-tools - Install required development tools"
	@echo ""

# Format code
format:
	@echo "Formatting Go code..."
	$(GO) tool $(TOOLS_MOD) golangci-lint fmt --config=$(LINT_CONFIG) $(GO_PACKAGES)
	@set -e; for module in $(EXAMPLE_MODULES); do \
		(cd "$$module" && $(GO) tool $(TOOLS_MOD) golangci-lint fmt --config=$(LINT_CONFIG)); \
	done
	@echo "Format complete"

# Run tests with coverage
test:
	@echo "Running tests..."
	@$(GO) test -v -race -coverprofile=coverage.out -covermode=atomic $(GO_PACKAGES)
	@set -e; for module in $(EXAMPLE_MODULES); do (cd "$$module" && $(GO) test ./...); done
	@echo "Tests complete"

# Run linter
lint:
	@echo "Running golangci-lint..."
	$(GO) tool $(TOOLS_MOD) golangci-lint run --config=$(LINT_CONFIG) $(GO_PACKAGES)
	@set -e; for module in $(EXAMPLE_MODULES); do \
		(cd "$$module" && $(GO) tool $(TOOLS_MOD) golangci-lint run --config=$(LINT_CONFIG)); \
	done
	@echo "Lint complete"

# Run go vet
vet:
	@echo "Running go vet..."
	@$(GO) vet ./...
	@echo "Vet complete"

# Generate and display coverage report
coverage: test
	@echo "Generating coverage report..."
	@$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"
	@$(GO) tool cover -func=coverage.out

# Clean test cache and coverage files
clean:
	@echo "Cleaning test cache and coverage files..."
	@$(GO) clean -testcache
	@rm -f coverage.out coverage.html
	@echo "Clean complete"

# Install development tools
install-tools:
	@echo "Installing development tools..."
	@$(GO) mod download $(TOOLS_MOD)
	@echo "Tools installed successfully"

.PHONY: fmt
fmt: format
