PY ?= python3
VENV ?= .venv
BIN := $(VENV)/bin
LOCAL_URI ?= mongodb://localhost:27099/?directConnection=true
LOCAL_DEPLOYMENT ?= mongoops-regex-test
ATLAS_CLUSTER ?= cluster-free
# probe-* knobs: window, optional namespace filter, view, and any extra mongoops flags
SINCE ?= 24h
NAMESPACE ?=
VIEW ?= summary
ARGS ?=
NS_FLAG = $(if $(NAMESPACE),-n "$(NAMESPACE)",)
# Every probe / test writes a self-contained HTML dashboard here (git-ignored) and refreshes
# <target>-latest.html, so `open reports/probe-atlas-latest.html` always shows the newest run.
REPORT_DIR ?= reports
STAMP := $(shell date -u +%Y%m%dT%H%M%SZ)
REPORT = $(REPORT_DIR)/$@-$(STAMP).html
LATEST = $(REPORT_DIR)/$@-latest.html
link_latest = ln -sf "$(notdir $(REPORT))" "$(LATEST)"

.PHONY: venv install test test-integration test-atlas-local test-atlas-live lint typecheck check \
        probe-atlas probe-local probe-waf atlas-local-up atlas-local-seed atlas-local-down

venv:
	$(PY) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip

install: venv
	$(BIN)/pip install -e ".[dev]"

test:
	$(BIN)/pytest -q

test-integration:
	MONGOOPS_TEST_MONGODB_URI="$(LOCAL_URI)" $(BIN)/pytest -q -m integration

# One-shot end-to-end checks. Both leave nothing behind except the atlas-local deployment.
#   make test-atlas-local                      # starts the local deployment if missing, seeds, tests
#   make test-atlas-live ATLAS_CLUSTER=<name>  # real cluster via Performance Advisor (~5-10 min)
test-atlas-local:
	@state="$$(atlas deployments list 2>/dev/null | awk '$$1=="$(LOCAL_DEPLOYMENT)" {print $$NF}')"; \
	case "$$state" in \
	  IDLE|RUNNING) ;; \
	  "") $(MAKE) atlas-local-up ;; \
	  *) echo "starting $(LOCAL_DEPLOYMENT) (state $$state)"; \
	     atlas deployments start $(LOCAL_DEPLOYMENT) && sleep 5 ;; \
	esac
	$(MAKE) test-integration
	$(MAKE) atlas-local-seed

test-atlas-live:
	BIN="$(BIN)" HTML_REPORT="$(REPORT)" scripts/dev/atlas_live_check.sh "$(ATLAS_CLUSTER)"
	@$(link_latest)

# Read-only probes: no seeding, no waiting, just report what is there right now.
#   make probe-atlas                                   # Performance Advisor, last 24h, summary
#   make probe-atlas ATLAS_CLUSTER=Cluster0 SINCE=7d NAMESPACE=app.orders VIEW=both
#   make probe-atlas ARGS="-f csv --output /tmp/regex.csv"
#   make probe-local                                   # atlas-local via getLog (buffer covers only
#                                                      # the last ~8 min on atlas-local, see README)
probe-atlas:
	$(BIN)/mongoops regex-finder atlas -c "$(ATLAS_CLUSTER)" --since "$(SINCE)" $(NS_FLAG) \
	  --view $(VIEW) --html "$(REPORT)" $(ARGS)
	@$(link_latest)

probe-local:
	$(BIN)/mongoops regex-finder live --uri "$(LOCAL_URI)" $(NS_FLAG) --view $(VIEW) \
	  --html "$(REPORT)" $(ARGS)
	@$(link_latest)

# WAF readiness scorecard for one cluster (read-only Admin API calls).
#   make probe-waf ATLAS_CLUSTER=Cluster0
#   make probe-waf ATLAS_CLUSTER=Cluster0 POLICY=landing-zone.prod.yaml ARGS="--fail-on fail"
POLICY ?=
POLICY_FLAG = $(if $(POLICY),--policy "$(POLICY)",)
probe-waf:
	$(BIN)/mongoops waf-check atlas -c "$(ATLAS_CLUSTER)" $(POLICY_FLAG) --html "$(REPORT)" $(ARGS)
	@$(link_latest)

lint:
	$(BIN)/ruff format --check src tests
	$(BIN)/ruff check src tests

typecheck:
	$(BIN)/mypy src

check: lint typecheck test

# --- atlas-local helpers (Atlas CLI + Docker required) ---
atlas-local-up:
	atlas deployments setup $(LOCAL_DEPLOYMENT) --type local --mdbVersion 8.0 --port 27099 --force

atlas-local-seed:
	mongosh "$(LOCAL_URI)" --quiet --file scripts/dev/seed_regex_workload.js > /dev/null
	$(BIN)/mongoops regex-finder live --uri "$(LOCAL_URI)" -n mongoops_test.customers --view summary \
	  --html "$(REPORT_DIR)/test-atlas-local-$(STAMP).html"
	@ln -sf "test-atlas-local-$(STAMP).html" "$(REPORT_DIR)/test-atlas-local-latest.html"

atlas-local-down:
	atlas deployments delete $(LOCAL_DEPLOYMENT) --force
