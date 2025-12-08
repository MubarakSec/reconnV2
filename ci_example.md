# Example CI pipeline

Minimal GitHub Actions-style steps to lint, test, and run the smoke pipeline:

```yaml
name: recon-cli CI
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.10"
      - name: Install deps
        run: |
          python -m pip install --upgrade pip
          python -m pip install -e .
          python -m pip install pytest
      - name: Lint (optional)
        run: |
          python -m pip install ruff
          ruff check .
      - name: Run tests
        run: python -m pytest
      - name: Smoke pipeline
        env:
          RECON_HOME: ${{ github.workspace }}/.recon_home
        run: |
          mkdir -p $RECON_HOME
          python -m pytest tests/smoke/test_smoke_pipeline.py
```

Notes:
- External recon binaries (subfinder, amass, httpx, etc.) are not required for the tests; pipeline gracefully skips missing tools.
- Adjust python-version as needed; add caches for pip/ruff if desired.
- For other CI systems (GitLab/Jenkins), replicate the steps: install deps → lint → pytest → smoke pipeline with `RECON_HOME` set to a writable path.
