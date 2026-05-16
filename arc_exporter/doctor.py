"""``arc-exporter doctor`` — environment self-check.

Runs every precondition we know about and prints a green/red table. Returns a non-zero
exit code if any required check fails.
"""

from __future__ import annotations

import shutil
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from arc_exporter.errors import ArcExporterError
from arc_exporter.guards.running_browser import running_browsers
from arc_exporter.secrets import first_available_secret
from arc_exporter.source import get_source
from arc_exporter.targets import available_targets


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str = ""


def _check(name: str, fn: Callable[[], CheckResult]) -> CheckResult:
    try:
        return fn()
    except ArcExporterError as e:
        return CheckResult(name=name, ok=False, detail=str(e))
    except Exception as e:  # surface anything else as a failure
        return CheckResult(name=name, ok=False, detail=f"unexpected: {e!r}")


def run_doctor(*, check_targets: bool = False) -> list[CheckResult]:
    """Run all preflight checks.

    ``check_targets=True`` additionally probes each installed Chromium-family
    target's Safe Storage entry. We don't do this by default because each lookup
    triggers a macOS Keychain permission prompt for the Python process.
    """
    results: list[CheckResult] = []

    def arc_present() -> CheckResult:
        src = get_source()
        if src.is_installed():
            n = len(src.profiles())
            return CheckResult("Arc installed", True, f"{n} profile(s) at {src.config.user_data_dir}")
        return CheckResult("Arc installed", False, f"not found at {src.config.user_data_dir}")

    def secrets_backend() -> CheckResult:
        secret = first_available_secret(("Arc Safe Storage", "Chrome Safe Storage", "Chromium Safe Storage"))
        if secret:
            return CheckResult("Keychain accessible", True, "Arc/Chrome Safe Storage key found")
        return CheckResult("Keychain accessible", False, "No Arc/Chrome Safe Storage key found")

    def browsers_idle() -> CheckResult:
        running = running_browsers()
        if not running:
            return CheckResult("Browsers quit", True, "no Arc/Chrome/Brave/... running")
        names = ", ".join(b.name for b in running)
        return CheckResult("Browsers quit", False, f"running: {names}")

    def disk_space_ok() -> CheckResult:
        free = shutil.disk_usage(".").free
        gb = free / (1024**3)
        if free < 5 * 1024**3:
            return CheckResult("Disk space", False, f"only {gb:.1f} GB free; >5 GB recommended")
        return CheckResult("Disk space", True, f"{gb:.1f} GB free")

    def python_version_ok() -> CheckResult:
        # ``arc_exporter`` requires >= 3.10 in pyproject.toml; this is a runtime
        # smoke-check for users running via a wrong interpreter.
        meets = sys.version_info[:2] >= (3, 10)
        return CheckResult(
            "Python >= 3.10",
            meets,
            f"{sys.version.split()[0]}" if meets else f"have {sys.version.split()[0]}",
        )

    def targets_present() -> CheckResult:
        avail = available_targets()
        if avail:
            return CheckResult("Targets detected", True, ", ".join(sorted(avail)))
        return CheckResult("Targets detected", False, "no supported target browser installed")

    def target_safe_storage() -> CheckResult:
        """For every installed Chromium-family target, verify a Safe Storage key exists.

        Without a keychain entry the target browser has never run, which means
        credentials cannot be re-encrypted and migration will leave logins empty.
        """
        from arc_exporter.targets.chromium import ChromiumTarget

        avail = available_targets()
        chromium = {k: t for k, t in avail.items() if isinstance(t, ChromiumTarget)}
        if not chromium:
            return CheckResult(
                "Target Safe Storage", True, "no Chromium-family targets installed (nothing to migrate)"
            )
        ok: list[str] = []
        missing: list[str] = []
        for name, tgt in sorted(chromium.items()):
            secret = first_available_secret(tgt.keychain_services())
            (ok if secret else missing).append(name)
        if not missing:
            return CheckResult("Target Safe Storage", True, f"key present for: {', '.join(ok)}")
        hint = (
            f"missing: {', '.join(missing)} — launch each of those browsers once so "
            "they create their keychain entry, then re-run doctor"
        )
        return CheckResult("Target Safe Storage", False, hint)

    checks: list[tuple[str, Callable[[], CheckResult]]] = [
        ("Python", python_version_ok),
        ("Arc", arc_present),
        ("Secrets", secrets_backend),
        ("Browsers", browsers_idle),
        ("Disk", disk_space_ok),
        ("Targets", targets_present),
    ]
    if check_targets:
        checks.append(("Target Safe Storage", target_safe_storage))
    for name, fn in checks:
        results.append(_check(name, fn))
    return results


def doctor_exit_code(results: Sequence[CheckResult]) -> int:
    return 0 if all(r.ok for r in results) else 1
