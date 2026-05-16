# Contributing to arc-exporter

Thanks for considering a contribution! arc-exporter exists to give users  
leaving Arc Browser a safe, reliable migration path.

## Quick start

```bash
git clone https://github.com/mhadifilms/arc-exporter
cd arc-exporter
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
pytest
```

## Development checklist

Before opening a PR, make sure:

- `pytest` passes (`pytest --cov=arc_exporter`).
- `ruff check .` and `ruff format --check .` are clean.
- `mypy arc_exporter` is clean (or no new errors).
- `CHANGELOG.md` has an entry describing the change.
- New behaviour has at least one test.

## Reporting bugs

Please open an issue with:

1. Your OS + version (`sw_vers` on macOS).
2. Python version (`python3 --version`).
3. arc-exporter version (`arc-exporter --version`).
4. The exact command you ran (with `--verbose`).
5. The end-of-run summary table or any traceback.

**Never** paste raw passwords, cookies, or `Local State` files into issues. Redact first.

## Security disclosures

See [SECURITY.md](SECURITY.md). Do **not** open public issues for security vulnerabilities.

## Code style

- Type hints on every public function.
- Format: `ruff format` (replaces Black). Line length 110.
- Imports: `ruff check --fix --select I` sorts them.
- One feature per PR; rebase onto `main` before review.

## Adding a new browser target

1. Subclass `arc_exporter.targets.base.Target`.
2. Register it in `arc_exporter.targets.registry.TARGETS`.
3. Add a fixture-driven test in `tests/targets/test_<name>.py`.
4. Document it in `docs/targets/<name>.md`.

## License

By contributing, you agree your contributions are licensed under the [MIT License](LICENSE).