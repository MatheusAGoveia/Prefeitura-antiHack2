.PHONY: install lint test test-integration docker-up docker-down clean

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

docker-up:
	docker-compose -f docker/compose/docker-compose.yml up -d

docker-down:
	docker-compose -f docker/compose/docker-compose.yml down -v

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".mypy_cache" -exec rm -rf {} +
	find . -type d -name ".ruff_cache" -exec rm -rf {} +
	rm -rf .coverage
