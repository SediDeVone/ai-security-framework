.PHONY: help install-harness start-scanner docker-up docker-down test

help:
	@echo "AI Security Framework Commands:"
	@echo "  make install-harness  - Install hooks & settings into ~/.claude/"
	@echo "  make start-scanner    - Run local scanner daemon"
	@echo "  make docker-up        - Start scanner service via Docker Compose"
	@echo "  make docker-down      - Stop scanner Docker container"
	@echo "  make test             - Run sanity & health checks against scanner"

install-harness:
	@mkdir -p ~/.claude/hooks ~/.claude/nova-rules ~/.claude/commands ~/.claude/agents
	@cp harness/hooks/*.py harness/hooks/*.sh ~/.claude/hooks/ && chmod +x ~/.claude/hooks/*
	@cp rules/*.nov ~/.claude/nova-rules/
	@cp harness/commands/strip-pii.md ~/.claude/commands/
	@cp harness/agents/untrusted-reader.md ~/.claude/agents/
	@echo "Harness installed! Remember to merge harness/settings.json into ~/.claude/settings.json."

start-scanner:
	python3 scanner/scanner_service.py

docker-up:
	docker-compose -f scanner/docker-compose.yml up -d --build

docker-down:
	docker-compose -f scanner/docker-compose.yml down

test:
	@echo "Testing /health endpoint..."
	@curl -s http://127.0.0.1:8901/health | jq .
	@echo "Testing PII redaction..."
	@curl -s -X POST http://127.0.0.1:8901/redact -H 'Content-Type: application/json' -d '{"text":"Contact John Smith at john@acme.com"}' | jq .

kill-switch:
	@echo "Activating emergency kill-switch..."
	@curl -s -X POST http://127.0.0.1:8901/kill-switch -H 'Content-Type: application/json' -d '{"active": true}' | jq .

kill-switch-off:
	@echo "Deactivating emergency kill-switch..."
	@curl -s -X POST http://127.0.0.1:8901/kill-switch -H 'Content-Type: application/json' -d '{"active": false}' | jq .

redteam:
	@echo "Running pre-deploy red-teaming evaluation via promptfoo..."
	@npx promptfoo@latest redteam run -c redteam/promptfoo.yaml
