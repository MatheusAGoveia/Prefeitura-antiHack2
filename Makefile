.PHONY: install lint test test-integration docker-up docker-down clean core-run core-test core-migrate

install:
	poetry install

lint:
	poetry run ruff check src tests
	poetry run black --check src tests
	poetry run mypy src

test:
	poetry run pytest tests/unit

test-integration:
	poetry run pytest tests/integration

core-run:
	poetry run uvicorn src.api.main:app --reload --port 8000

core-test:
	poetry run pytest tests/unit/test_core.py tests/integration/test_db_integration.py

core-migrate:
	poetry run alembic upgrade head

docker-up:
	docker compose -f docker/compose/docker-compose.yml up -d

docker-down:
	docker compose -f docker/compose/docker-compose.yml down -v

preflight-check:
	poetry run python scripts/validate_alertmanager_deploy.py

render-alertmanager:
	poetry run python scripts/render_alertmanager_config.py

deploy-production: preflight-check
	docker compose -f docker/compose/docker-compose.yml -f docker/compose/docker-compose.production.yml up -d

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".mypy_cache" -exec rm -rf {} +
	find . -type d -name ".ruff_cache" -exec rm -rf {} +
	rm -rf .coverage

