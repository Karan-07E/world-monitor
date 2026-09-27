.PHONY: build test run demo clean lint docker-build docker-up docker-down benchmark

# ============================================================
# Variables
# ============================================================
BINARY       := server
MODULE       := github.com/cryptoattr/secure-doc-dist
GO           := go
GOFLAGS      := -v
CGO_ENABLED  := 1
SERVER_PORT  := 8080
BASE_URL     := http://localhost:$(SERVER_PORT)

# ============================================================
# Build
# ============================================================
build:
	@echo "==> Building $(BINARY)..."
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(GOFLAGS) -o bin/$(BINARY) ./cmd/server/

# ============================================================
# Test
# ============================================================
test:
	@echo "==> Running tests..."
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test $(GOFLAGS) ./internal/crypto/... ./internal/keystore/... ./internal/fabric/... ./internal/watermark/...

test-all:
	@echo "==> Running all tests..."
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test $(GOFLAGS) ./...

test-crypto:
	@echo "==> Running crypto tests..."
	$(GO) test -v ./internal/crypto/...

test-watermark:
	@echo "==> Running watermark tests..."
	CGO_ENABLED=1 $(GO) test -v ./internal/watermark/...

test-fabric:
	@echo "==> Running fabric tests..."
	$(GO) test -v ./internal/fabric/...

test-cover:
	@echo "==> Running tests with coverage..."
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test -coverprofile=coverage.out ./internal/...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# ============================================================
# Run
# ============================================================
run: build
	@echo "==> Starting server on port $(SERVER_PORT)..."
	DISABLE_MINIO=true LOG_LEVEL=debug ./bin/$(BINARY)

# ============================================================
# Demo
# ============================================================
demo: build
	@echo ""
	@echo "=================================================="
	@echo "  SECURE DOCUMENT DISTRIBUTION DEMO"
	@echo "  Cryptographic Attribution System"
	@echo "=================================================="
	@echo ""
	@bash scripts/demo-e2e.sh

demo-standalone: build
	@echo ""
	@echo "=================================================="
	@echo "  STANDALONE DEMO (no Docker required)"
	@echo "=================================================="
	@echo ""
	@bash scripts/demo-standalone.sh

# ============================================================
# Docker
# ============================================================
docker-build:
	@echo "==> Building Docker image..."
	docker build -t secure-doc-dist:latest .

docker-up: docker-build
	@echo "==> Starting infrastructure..."
	docker compose up -d

docker-down:
	@echo "==> Stopping infrastructure..."
	docker compose down -v

# ============================================================
# Clean
# ============================================================
clean:
	@echo "==> Cleaning..."
	rm -rf bin/
	rm -f coverage.out coverage.html
	docker compose down -v 2>/dev/null || true

# ============================================================
# Lint
# ============================================================
lint:
	@echo "==> Running linter..."
	golangci-lint run ./...

# ============================================================
# Benchmark
# ============================================================
benchmark:
	@echo "==> Running benchmarks..."
	$(GO) test -bench=. -benchtime=3s ./internal/crypto/... ./internal/watermark/...

# ============================================================
# Dependencies
# ============================================================
deps:
	@echo "==> Installing dependencies..."
	$(GO) mod download
	$(GO) mod tidy

# ============================================================
# Offline Bundle
# ============================================================
offline-bundle:
	@echo "==> Building offline bundle..."
	@bash scripts/build-offline-bundle.sh

# ============================================================
# Help
# ============================================================
help:
	@echo "Available targets:"
	@echo "  build           - Build the server binary"
	@echo "  test            - Run core tests"
	@echo "  test-all        - Run all tests"
	@echo "  test-crypto     - Run crypto tests only"
	@echo "  test-watermark  - Run watermark tests only"
	@echo "  test-fabric     - Run fabric tests only"
	@echo "  test-cover      - Run tests with coverage"
	@echo "  run             - Build and run server locally"
	@echo "  demo            - Run full E2E demo"
	@echo "  demo-standalone - Run standalone demo (no Docker)"
	@echo "  docker-build    - Build Docker image"
	@echo "  docker-up       - Start all services"
	@echo "  docker-down     - Stop all services"
	@echo "  clean           - Clean build artifacts"
	@echo "  benchmark       - Run benchmarks"
	@echo "  deps            - Download dependencies"
	@echo "  offline-bundle  - Create offline deployment bundle"
