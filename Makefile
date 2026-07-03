.PHONY: build run test lint clean docker dev help

APP_NAME := webtool
BUILD_DIR := build

help: ## Show available commands
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

dev: ## Run in development mode
	go run main.go

build: ## Build the binary
	@mkdir -p $(BUILD_DIR)
	go build -ldflags="-s -w" -o $(BUILD_DIR)/$(APP_NAME) main.go

build-all: ## Build for multiple platforms
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(APP_NAME)-linux-amd64 main.go
	GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(APP_NAME)-linux-arm64 main.go
	GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(APP_NAME)-darwin-amd64 main.go
	GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(APP_NAME)-darwin-arm64 main.go
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(APP_NAME)-windows-amd64.exe main.go

run: build ## Build and run
	./$(BUILD_DIR)/$(APP_NAME)

test: ## Run tests
	go test -v -race -cover ./...

test-short: ## Run short tests
	go test -v -short ./...

bench: ## Run benchmark tests
	go test -bench=. -benchmem ./...

lint: ## Run linters
	golangci-lint run ./...
	go vet ./...

tidy: ## Tidy modules
	go mod tidy
	go mod verify

clean: ## Clean build artifacts
	rm -rf $(BUILD_DIR)
	rm -rf reports/
	go clean -cache

docker: ## Build Docker image
	docker build -t $(APP_NAME):latest .

docker-compose: ## Run with Docker Compose
	docker-compose up --build

install: ## Install to GOPATH
	go install .

release: lint test build-all ## Build for release

cover: ## Run tests with coverage report
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

profile: ## Run CPU profiling
	go test -bench=. -cpuprofile=cpu.out -memprofile=mem.out ./...
	go tool pprof -http=:8081 cpu.out
