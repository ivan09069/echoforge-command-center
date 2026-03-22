.PHONY: verify test count lint clean

# ═══════════════════════════════════════════════════════════════════════════
# CI parity — run exactly what CI runs, in one command
# ═══════════════════════════════════════════════════════════════════════════

REQUIRED_TEST_COUNT := 748

verify: test count
	@echo ""
	@echo "✅ VERIFY PASSED — safe to merge"

test:
	@echo "Running full test suite..."
	@python -m pytest tests/ -q --tb=short

count:
	@ACTUAL=$$(python -m pytest tests/ --co -q 2>&1 | grep -oP '^\d+(?= tests)'); \
	if [ "$$ACTUAL" -lt $(REQUIRED_TEST_COUNT) ]; then \
		echo "❌ Test count $$ACTUAL < required $(REQUIRED_TEST_COUNT)"; \
		exit 1; \
	else \
		echo "✅ Test count: $$ACTUAL (≥$(REQUIRED_TEST_COUNT))"; \
	fi

# ═══════════════════════════════════════════════════════════════════════════
# Utilities
# ═══════════════════════════════════════════════════════════════════════════

stats:
	@echo "=== Project ==="
	@echo "Prod:  $$(cat *.py | wc -l) lines"
	@echo "Tests: $$(cat tests/*.py | wc -l) lines"
	@echo "Docs:  $$(cat *.md | wc -l) lines"
	@echo "Total: $$(find . -name '*.py' -o -name '*.md' | xargs cat | wc -l) lines"
	@python -m pytest tests/ --co -q 2>&1 | tail -1

clean:
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	@echo "Cleaned."
