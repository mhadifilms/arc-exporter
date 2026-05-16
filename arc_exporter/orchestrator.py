"""Top-level orchestration: source → exports → target."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from arc_exporter.crypto import derive_v10_key
from arc_exporter.errors import CryptoError, SecretsBackendError
from arc_exporter.export.amo_mapping import build_policies_json, fetch_browser_mappings
from arc_exporter.export.bookmarks_html import write_bookmarks_html
from arc_exporter.export.cards_csv import write_cards_csv
from arc_exporter.export.cookies_json import write_cookies_json
from arc_exporter.export.cookies_sqlite import write_cookies_sqlite
from arc_exporter.export.easels_md import collect_easel_notes, write_easels_md
from arc_exporter.export.extensions_html import write_extensions_html
from arc_exporter.export.history_export import write_history_html, write_history_json
from arc_exporter.export.open_tabs_json import write_open_tabs_json
from arc_exporter.export.passwords_csv import write_passwords_csv
from arc_exporter.guards.backups import BackupManager
from arc_exporter.parsers.cookies import iter_cookies
from arc_exporter.parsers.extensions import list_extensions
from arc_exporter.parsers.history import iter_history
from arc_exporter.parsers.login_data import iter_logins
from arc_exporter.parsers.sidebar import load_sidebar
from arc_exporter.parsers.web_data import iter_credit_cards
from arc_exporter.secrets import first_available_secret
from arc_exporter.source import get_source
from arc_exporter.source.base import ArcProfile
from arc_exporter.util import ensure_dir, now_stamp, safe_dir_name

log = logging.getLogger("arc_exporter.orchestrator")


def _default_output_root() -> Path:
    """Return the default location for exported artefacts.

    Uses ``platformdirs`` so the path is OS-appropriate (e.g. ``~/Library/Application
    Support/arc-exporter`` on macOS) instead of polluting the user's current working
    directory.
    """
    try:
        from platformdirs import user_data_path

        return Path(user_data_path("arc-exporter", appauthor=False)) / "exports"
    except ImportError:
        return Path.home() / "arc-export"


@dataclass
class ProfileExport:
    profile: ArcProfile
    out_dir: Path
    artefacts: dict[str, Path] = field(default_factory=dict)
    counts: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


@dataclass
class RunResult:
    run_dir: Path
    timestamp: str
    profiles: list[ProfileExport] = field(default_factory=list)

    def per_kind_totals(self) -> dict[str, int]:
        totals: dict[str, int] = {}
        for pe in self.profiles:
            for k, v in pe.counts.items():
                totals[k] = totals.get(k, 0) + v
        return totals


@dataclass
class ExportOptions:
    bookmarks: bool = True
    passwords: bool = True
    cards: bool = True
    cookies: bool = False
    history: bool = False
    tabs: bool = False
    extensions: bool = True
    easels: bool = False
    amo_mapping: bool = False
    dry_run: bool = False
    arc_root: Path | None = None
    output_root: Path | None = None
    profiles_filter: tuple[str, ...] = ()


class Orchestrator:
    def __init__(self, options: ExportOptions) -> None:
        self.options = options
        self.source = get_source(options.arc_root)
        self.timestamp = now_stamp()
        root = options.output_root or _default_output_root()
        self.run_dir = ensure_dir(root / "runs" / self.timestamp)
        self.backups = BackupManager(root)
        self._update_latest_symlink(root)
        self._aes_key_cache: bytes | None = None

    def _update_latest_symlink(self, root: Path) -> None:
        latest = root / "latest"
        try:
            if latest.is_symlink() or latest.exists():
                latest.unlink()
            latest.symlink_to(self.run_dir.relative_to(root))
        except OSError:
            # Windows / restricted filesystems just skip the symlink; not critical.
            pass

    def _arc_key(self) -> bytes | None:
        if self._aes_key_cache is not None:
            return self._aes_key_cache
        try:
            secret = first_available_secret(self.source.safe_storage_services())
        except SecretsBackendError as e:
            log.warning("secrets backend unavailable: %s", e)
            return None
        if not secret:
            log.warning("no Arc Safe Storage key found; encrypted fields will not be decrypted")
            return None
        try:
            self._aes_key_cache = derive_v10_key(secret)
        except CryptoError as e:
            log.warning("derive_v10_key failed: %s", e)
            return None
        return self._aes_key_cache

    def run(self) -> RunResult:
        profiles = self.source.profiles()
        if self.options.profiles_filter:
            wanted = set(self.options.profiles_filter)
            profiles = [p for p in profiles if p.display_name in wanted or p.directory_name in wanted]
        log.info("found %d Arc profile(s)", len(profiles))
        result = RunResult(run_dir=self.run_dir, timestamp=self.timestamp)
        sidebar = load_sidebar(self.source.config.sidebar_path)
        amo_mapping = None
        if self.options.amo_mapping and not self.options.dry_run:
            try:
                amo_mapping = fetch_browser_mappings()
            except Exception as e:
                log.warning("AMO mapping fetch failed: %s", e)

        for profile in profiles:
            pe = self._export_one(profile, sidebar, amo_mapping)
            result.profiles.append(pe)
        return result

    def _export_one(self, profile: ArcProfile, sidebar, amo_mapping) -> ProfileExport:
        prof_dir = ensure_dir(self.run_dir / "profiles" / safe_dir_name(profile.display_name))
        pe = ProfileExport(profile=profile, out_dir=prof_dir)
        ts = self.timestamp
        aes_key = self._arc_key()
        log.info(
            "exporting profile %r (dir=%s) -> %s",
            profile.display_name,
            profile.directory_name,
            prof_dir,
        )

        if self.options.bookmarks:
            out = prof_dir / f"bookmarks_{ts}.html"
            spaces = sidebar.for_profile(profile.directory_name) or sidebar.spaces
            if self.options.dry_run:
                pe.counts["bookmarks"] = sum(len(s.pinned) for s in spaces)
            else:
                write_bookmarks_html(out, spaces)
                pe.artefacts["bookmarks"] = out
                pe.counts["bookmarks"] = sum(len(s.pinned) for s in spaces)

        if self.options.passwords:
            out = prof_dir / f"passwords_{ts}.csv"
            if self.options.dry_run:
                pe.counts["passwords"] = sum(1 for _ in iter_logins(profile.login_data))
            else:
                written, failed = write_passwords_csv(out, iter_logins(profile.login_data), aes_key=aes_key)
                pe.artefacts["passwords"] = out
                pe.counts["passwords"] = written
                if failed:
                    pe.warnings.append(f"{failed} passwords could not be decrypted")

        if self.options.cards:
            out = prof_dir / f"cards_{ts}.csv"
            if self.options.dry_run:
                pe.counts["cards"] = sum(1 for _ in iter_credit_cards(profile.web_data))
            else:
                n = write_cards_csv(out, iter_credit_cards(profile.web_data), aes_key=aes_key)
                pe.artefacts["cards"] = out
                pe.counts["cards"] = n

        if self.options.cookies:
            out_sqlite = prof_dir / f"cookies_{ts}.sqlite"
            out_json = prof_dir / f"cookies_{ts}.json"
            if self.options.dry_run:
                pe.counts["cookies"] = sum(1 for _ in iter_cookies(profile.cookies))
            else:
                pe.counts["cookies"] = write_cookies_sqlite(
                    out_sqlite, iter_cookies(profile.cookies), aes_key=aes_key
                )
                pe.artefacts["cookies"] = out_sqlite
                write_cookies_json(out_json, iter_cookies(profile.cookies), aes_key=aes_key)
                pe.artefacts["cookies_json"] = out_json

        if self.options.history:
            out_json = prof_dir / f"history_{ts}.json"
            out_html = prof_dir / f"history_{ts}.html"
            if self.options.dry_run:
                pe.counts["history"] = sum(1 for _ in iter_history(profile.history, limit=10))
            else:
                pe.counts["history"] = write_history_json(out_json, iter_history(profile.history))
                write_history_html(out_html, iter_history(profile.history))
                pe.artefacts["history"] = out_json
                pe.artefacts["history_html"] = out_html

        if self.options.tabs:
            out = prof_dir / f"open_tabs_{ts}.json"
            spaces = sidebar.for_profile(profile.directory_name) or sidebar.spaces
            if self.options.dry_run:
                pe.counts["tabs"] = sum(len(s.today_tabs) for s in spaces)
            else:
                pe.counts["tabs"] = write_open_tabs_json(out, spaces)
                pe.artefacts["tabs"] = out

        if self.options.extensions:
            exts = list_extensions(profile.path)
            out_html = prof_dir / f"extensions_{ts}.html"
            if self.options.dry_run:
                pe.counts["extensions"] = len(exts)
            else:
                pe.counts["extensions"] = write_extensions_html(
                    out_html, exts, profile_name=profile.display_name, amo_mappings=amo_mapping
                )
                pe.artefacts["extensions"] = out_html
                if amo_mapping is not None:
                    matched = []
                    for e in exts:
                        m = amo_mapping.get(e.chrome_id)
                        if m:
                            matched.append({"guid": m.get("guid"), "slug": m.get("slug"), "name": e.name})
                    policies_path = prof_dir / f"policies_{ts}.json"
                    import json as _json

                    policies_path.write_text(
                        _json.dumps(build_policies_json(matched), indent=2),
                        encoding="utf-8",
                    )
                    pe.artefacts["policies"] = policies_path

        if self.options.easels:
            out = prof_dir / f"easels_{ts}.md"
            records = list(collect_easel_notes(profile.path))
            if self.options.dry_run:
                pe.counts["easels"] = len(records)
            else:
                pe.counts["easels"] = write_easels_md(out, records)
                pe.artefacts["easels"] = out

        return pe
