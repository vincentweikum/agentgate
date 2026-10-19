.PHONY: setup run test spec lint contract evals check

PY := .venv/bin/python

setup:      ## install everything and create local secrets in .env
	python3 -m venv .venv
	$(PY) -m pip install -r requirements-dev.txt
	npm ci --no-audit --no-fund
	$(PY) scripts/dev_setup.py

run:        ## start the API at http://localhost:8000 (docs at /docs)
	.venv/bin/uvicorn app.main:app --reload

test:       ## unit tests
	$(PY) -m pytest

spec:       ## regenerate the OpenAPI spec and Postman collection from the code
	$(PY) scripts/export_openapi.py
	$(PY) scripts/postman.py

lint:       ## API standards + OWASP lint, with exceptions applied
	$(PY) scripts/governance_lint.py

contract:   ## contract tests against a running copy of the API
	$(PY) scripts/contract_test.py

evals:      ## agent guardrail scenarios
	$(PY) -m evals.run

check:      ## what CI runs (the breaking-change check runs on pull requests)
	$(PY) scripts/export_openapi.py --check
	$(PY) scripts/catalog.py validate
	$(PY) scripts/postman.py && git diff --exit-code postman/
	$(PY) scripts/governance_lint.py
	$(PY) -m pytest
	$(PY) scripts/contract_test.py
	$(PY) -m evals.run
	$(PY) -m agent_gateway.audit verify --path reports/eval-audit.jsonl
	.venv/bin/bandit -r app agent_gateway -ll -q
	.venv/bin/pip-audit -r requirements.txt --progress-spinner off
