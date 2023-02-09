.PHONY: format
format:
	poetry run isort sec_sem8 tests
	poetry run black --config=pyproject.toml sec_sem8 tests

.PHONY: lint
lint:
	poetry run black --config=pyproject.toml --check sec_sem8 tests
	poetry run mypy sec_sem8

.PHONY: test
test:
	poetry run pytest