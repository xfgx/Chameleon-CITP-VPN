# Chameleon CITP — сборка, тесты, проверки безопасности
# Требования: Go >= 1.26 (см. go.mod). Внешние зависимости: Wintun (только Windows).

GO       ?= go
GOLINT   ?= golangci-lint
GITLEAKS ?= gitleaks
GOVULN   ?= govulncheck

.PHONY: all build test vet lint security vuln e2e release clean

all: build

# Сборка всех пакетов модуля
build:
	$(GO) build ./...

# Тесты с race detector
test:
	$(GO) test -race ./...

# Статический анализ
vet:
	$(GO) vet ./...

# Линтер (требует golangci-lint)
lint:
	$(GOLINT) run

# Проверки безопасности: секреты + уязвимости зависимостей
security:
	$(GITLEAKS) detect --source .
	$(GOVULN) ./...

vuln:
	$(GOVULN) ./...

# Сквозной тест: сервер + клиент в Docker
e2e:
	docker compose -f test/e2e/docker-compose.yml up --abort-on-container-exit --exit-code-from e2e

# Кросс-сборка релизных бинарников
release:
	GOOS=linux   GOARCH=amd64 $(GO) build -trimpath -ldflags "-s -w" -o dist/cham-server-linux-amd64  ./cmd/cham-server
	GOOS=linux   GOARCH=amd64 $(GO) build -trimpath -ldflags "-s -w" -o dist/cham-client-linux-amd64  ./cmd/cham-client
	GOOS=linux   GOARCH=amd64 $(GO) build -trimpath -ldflags "-s -w" -o dist/cham-keygen-linux-amd64  ./cmd/cham-keygen
	GOOS=windows GOARCH=amd64 $(GO) build -trimpath -ldflags "-s -w" -o dist/chamd-windows-amd64.exe  ./cmd/chamd
	GOOS=darwin  GOARCH=arm64 $(GO) build -trimpath -ldflags "-s -w" -o dist/cham-client-darwin-arm64 ./cmd/cham-client
	cd dist && sha256sum * > checksums.txt

clean:
	rm -rf dist

# --- Свой сервер и бенчмарк -------------------------------------------------
LDF := -trimpath -ldflags "-s -w"
.PHONY: setup node bench-tools

# Мастер настройки для Linux и Windows → bin/chameleon-setup, bin/chameleon-setup.exe
setup:
	CGO_ENABLED=0 $(GO) build $(LDF) -o bin/chameleon-setup ./cmd/chameleon-setup
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build $(LDF) -o bin/chameleon-setup.exe ./cmd/chameleon-setup

# Бинарники ноды (Linux): хаб клиентов и плечо RU↔выход
node:
	CGO_ENABLED=0 GOOS=linux $(GO) build $(LDF) -o bin/ks-hub ./cmd/ks-hub
	CGO_ENABLED=0 GOOS=linux $(GO) build $(LDF) -o bin/ks-relay ./cmd/ks-relay

# Генератор нагрузки для bench/bench.sh
bench-tools: node
	CGO_ENABLED=0 GOOS=linux $(GO) build $(LDF) -o bin/ks-stress ./cmd/ks-stress
