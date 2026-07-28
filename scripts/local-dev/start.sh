#!/usr/bin/env bash
set -e

echo "=== GovSec Shield Local Dev Environment Startup ==="

echo "1. Subindo containers (PostgreSQL, Redpanda, Redis)..."
docker-compose -f docker/compose/docker-compose.yml up -d

echo "2. Aguardando banco de dados PostgreSQL..."
sleep 3

echo "3. Executando migrações do Alembic..."
poetry run alembic upgrade head

echo "=== Ambiente local iniciado com sucesso! ==="
