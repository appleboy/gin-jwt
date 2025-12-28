.PHONY: help run build clean test install-deps

# Default target
help:
	@echo "OAuth SSO Example - Available Commands:"
	@echo ""
	@echo "  make run          - Run the server"
	@echo "  make build        - Build the binary"
	@echo "  make clean        - Clean build artifacts"
	@echo "  make test         - Run tests"
	@echo "  make install-deps - Install dependencies"
	@echo "  make setup-env    - Create .env file from template"
	@echo ""

# Run the server
run:
	@echo "Starting OAuth SSO server..."
	@go run server.go

# Build the binary
build:
	@echo "Building OAuth SSO server..."
	@go build -o oauth-sso-server server.go
	@echo "Build complete: oauth-sso-server"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -f oauth-sso-server
	@go clean
	@echo "Clean complete"

# Run tests
test:
	@echo "Running tests..."
	@go test -v ./...

# Install dependencies
install-deps:
	@echo "Installing dependencies..."
	@go mod download
	@go mod tidy
	@echo "Dependencies installed"

# Setup environment file
setup-env:
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo ".env file created from .env.example"; \
		echo "Please edit .env and add your OAuth credentials"; \
	else \
		echo ".env file already exists"; \
	fi
