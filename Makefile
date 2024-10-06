.PHONY: all
all: tidy lint test test/cover

.PHONY: help
help: ## Display this help screen
	awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: tidy
tidy: ## Tidy
	go mod tidy -v
	go mod verify
	go fmt ./... 
	go vet ./...

.PHONY: lint
lint: ## Lint
	docker run -t --rm -v .:/app -v ~/.cache/golangci-lint/v1.61.0:/root/.cache -w /app golangci/golangci-lint:v1.61.0 golangci-lint run -v -c .golangci.yml

.PHONY: test
test: ## Test
	go test -race -buildvcs ./...

.PHONY: test/cover
test/cover: ## Test and cover
	go test -race -buildvcs -coverprofile=/tmp/coverage.out ./...
	go tool cover -html=/tmp/coverage.out
