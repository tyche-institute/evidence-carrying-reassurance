PY ?= python3

.PHONY: all gen run sums check test clean

all: gen run sums

gen:
	$(PY) verifier/gen_fixtures.py

run:
	$(PY) verifier/run_matrix.py

sums:
	find carrier fixtures policy expected spec verifier tests -type f ! -name '*.pyc' | LC_ALL=C sort | xargs sha256sum > SHA256SUMS

check:
	sha256sum -c --quiet SHA256SUMS
	$(PY) -m unittest discover -s tests -v

test:
	$(PY) -m unittest discover -s tests -v

clean:
	rm -rf expected fixtures policy carrier/local-xroad-dev/carrier-record.json SHA256SUMS
	find . -name __pycache__ -type d -exec rm -rf {} +
