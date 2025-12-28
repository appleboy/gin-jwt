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
	@if command -v golangci-lint > /dev/null; then \
		golangci-lint fmt ./...; \
	else \
		echo "golangci-lint not found!"; \
		echo "Run 'make install-tools' to install golangci-lint"; \
		exit 1; \
	fi
	@echo "Format complete"

# Run tests with coverage
test:
	@echo "Running tests..."
	@go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	@echo "Tests complete"

# Run linter
lint:
	@echo "Running golangci-lint..."
	@if command -v golangci-lint > /dev/null; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not found!"; \
		echo "Run 'make install-tools' to install golangci-lint"; \
		exit 1; \
	fi
	@echo "Lint complete"

# Run go vet
vet:
	@echo "Running go vet..."
	@go vet ./...
	@echo "Vet complete"

# Generate and display coverage report
coverage: test
	@echo "Generating coverage report..."
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"
	@go tool cover -func=coverage.out

# Clean test cache and coverage files
clean:
	@echo "Cleaning test cache and coverage files..."
	@go clean -testcache
	@rm -f coverage.out coverage.html
	@echo "Clean complete"

# Install development tools
install-tools:
	@echo "Installing development tools..."
	@go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	@echo "Tools installed successfully"
