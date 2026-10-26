# awesome-agent-skills. Every target is offline unless it says otherwise.
PY ?= python3
PORT ?= 8520

.PHONY: test build curate page check serve all harvest skills fresh og release

test:            ## offline unit tests
	$(PY) -m pytest tests -q

build:           ## validate curation/ against curation/schema.yaml, write data/catalog.json
	$(PY) pipeline/build.py

curate: build    ## build + README, docs/index.html, docs/catalog.js
	$(PY) pipeline/render.py

page: build      ## also dist/hub.html, one self-contained page to publish privately
	$(PY) pipeline/render.py --hub

harvest:         ## NETWORK: fetch the curated core from GitHub into ~/.cache/awesome-agent-skills/harvest/
	$(PY) -I pipeline/harvest.py

fresh:           ## NETWORK, metadata only: scanned commits vs authors' heads -> data/freshness.json (then make curate)
	$(PY) -I pipeline/freshness.py
	$(PY) -I pipeline/collect_freshness.py

skills:          ## parse the newest harvest run into data/skills.json (offline; render picks it up)
	$(PY) -I pipeline/skills.py

og:              ## docs/og.png social preview (needs Playwright), then re-render so the page links it
	$(PY) pipeline/og_image.py
	$(PY) pipeline/render.py

check:           ## denylist and em-dashes in every tracked or about-to-be-tracked text file
	$(PY) pipeline/check.py

serve:           ## the static site on loopback only
	$(PY) -m http.server $(PORT) --bind 127.0.0.1 --directory docs

GATE ?= $(HOME)/.claude/security/publish-gate.sh

release:         ## pre-release: tests, rebuild, checks, generated files committed, then the publish gate audit (changes nothing)
	$(MAKE) test curate check
	@git diff --quiet -- README.md docs data || { echo "release: generated files differ from the last commit; commit them first"; exit 1; }
	@if [ -x "$(GATE)" ]; then "$(GATE)" .; else echo "release: no publish gate at $(GATE); skipped"; fi

all: test page check
