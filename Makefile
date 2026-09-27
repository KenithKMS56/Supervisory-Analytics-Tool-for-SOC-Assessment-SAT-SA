.PHONY: check test lint typecheck format offline-bundle clean

check: lint typecheck test

lint:
	uv run ruff check src tests

format:
	uv run ruff format src tests

typecheck:
	uv run mypy src/satsa

test:
	uv run pytest tests -v

offline-bundle:
	uv run satsa offline-bundle

clean:
	rm -rf .pytest_cache .ruff_cache build dist *.egg-info data/generated
