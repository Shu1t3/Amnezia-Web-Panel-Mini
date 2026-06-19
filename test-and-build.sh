#!/usr/bin/env bash
set -euo pipefail

echo "=== Amnezia Web Panel Mini — Test & Build (Go) ==="
echo ""

# 1. Проверяем что Go доступен
echo "[1/6] Checking Go..."
if ! command -v go &>/dev/null; then
    echo "ERROR: go command not found"
    exit 1
fi
go version

# 2. Скачиваем зависимости
echo "[2/6] Downloading dependencies..."
go mod download

# 3. Запускаем форматирование и линтер (vet)
echo "[3/6] Running go fmt & go vet..."
go fmt ./...
go vet ./... || echo "WARNING: vet issues found"

# 4. Запускаем тесты
echo "[4/6] Running tests..."
go test ./... -v || {
    echo "ERROR: Tests failed!"
    exit 1
}

# 5. Проверяем Docker
echo "[5/6] Checking Docker..."
if ! command -v docker &>/dev/null; then
    echo "WARNING: Docker not found, skipping build"
    echo ""
    echo "=== All Go checks passed ==="
    exit 0
fi

# 6. Собираем Docker image
echo "[6/6] Building Docker image..."
docker build -t amnezia-panel:test . || {
    echo "ERROR: Docker build failed!"
    exit 1
}

echo ""
echo "=== All checks passed ==="
