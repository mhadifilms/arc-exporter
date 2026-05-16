"""Single Chromium-family target.

This one adapter handles Chrome, Brave, Edge, Vivaldi, Opera, Dia, Arc Search, Sidekick,
Comet — every Chromium fork shares the same on-disk layout, only the root directory and
Safe Storage keychain service name differ.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from arc_exporter.crypto import decrypt_v10, encrypt_v10, looks_like_v10
from arc_exporter.errors import CryptoError, TargetUnavailableError
from arc_exporter.guards.backups import BackupManager
from arc_exporter.parsers.login_data import iter_logins
from arc_exporter.parsers.web_data import iter_credit_cards
from arc_exporter.targets.base import (
    ArtefactKind,
    MigrationReport,
    MigrationRequest,
    Target,
    TargetProfile,
)
from arc_exporter.util import ensure_dir, safe_copy_tree

log = logging.getLogger("arc_exporter.targets.chromium")

# Heavy/cached subdirs we skip on copy unless --keep-cache-dirs is set.
_CACHE_SKIP = {
    "Cache",
    "Code Cache",
    "GPUCache",
    "Crashpad",
    "ShaderCache",
    "Service Worker",
    "Optimization Hints",
    "GrShaderCache",
    "Network Action Predictor",
    "Platform Notifications",
    "Reporting and NEL",
    "Top Sites-journal",
    "Visited Links",
    "Media Cache",
}

# Site/PWA storage. Skipping these breaks signed-in sessions; off by default in the
# new code (legacy stripped them unconditionally). User can opt in via --strip-storage.
_STORAGE_DIRS = {
    "IndexedDB",
    "Local Storage",
    "Session Storage",
    "Storage",
    "File System",
}


@dataclass
class ChromiumTarget(Target):
    name: str = ""
    family: str = "chromium"  # type: ignore[assignment]
    supports: tuple[ArtefactKind, ...] = ("bookmarks", "passwords", "cards", "cookies", "extensions")
    root_dir: Path = field(default_factory=Path)
    services: tuple[str, ...] = ()
    process: str = ""

    @property
    def user_data_dir(self) -> Path:
        return self.root_dir

    def keychain_services(self) -> tuple[str, ...]:
        return self.services

    def process_name(self) -> str:
        return self.process

    def is_installed(self) -> bool:
        return self.root_dir.exists()

    def _local_state(self) -> Path:
        return self.root_dir / "Local State"

    def create_profile(self, display_name: str, *, dry_run: bool = False) -> TargetProfile:
        """Allocate the next free ``Profile N`` directory under the target root."""
        if not self.is_installed():
            raise TargetUnavailableError(f"{self.name} is not installed at {self.root_dir}")
        used: set[int] = set()
        if self.root_dir.exists():
            for d in self.root_dir.iterdir():
                m = re.fullmatch(r"Profile (\d+)", d.name)
                if m:
                    used.add(int(m.group(1)))
        n = 1
        while n in used:
            n += 1
        dir_name = f"Profile {n}"
        path = self.root_dir / dir_name
        if dry_run:
            return TargetProfile(directory_name=dir_name, display_name=display_name, path=path)
        ensure_dir(path)
        return TargetProfile(directory_name=dir_name, display_name=display_name, path=path)

    def copy_arc_profile(
        self,
        arc_profile_path: Path,
        display_name: str,
        *,
        dry_run: bool = False,
        keep_cache_dirs: bool = False,
        strip_storage: bool = False,
    ) -> TargetProfile:
        """Copy an Arc profile into a brand-new target profile, atomically registered."""
        target = self.create_profile(display_name, dry_run=dry_run)
        if dry_run:
            return target

        # Remove the placeholder we just created so copytree can own the destination.
        if target.path.exists():
            shutil.rmtree(target.path)

        skip = set()
        if not keep_cache_dirs:
            skip |= _CACHE_SKIP
        if strip_storage:
            skip |= _STORAGE_DIRS
        final = safe_copy_tree(arc_profile_path, target.path, skip=skip)
        # safe_copy_tree may have picked a new name if there's a collision; reflect that.
        target = TargetProfile(directory_name=final.name, display_name=display_name, path=final)
        self._register_profile(target)
        return target

    def _register_profile(self, profile: TargetProfile) -> None:
        local_state = self._local_state()
        ensure_dir(self.root_dir)
        try:
            state = json.loads(local_state.read_text(encoding="utf-8")) if local_state.exists() else {}
        except (OSError, json.JSONDecodeError):
            state = {}
        state.setdefault("profile", {}).setdefault("info_cache", {})
        state["profile"]["info_cache"][profile.directory_name] = {
            "active_time": 0.0,
            "avatar_icon": "chrome://theme/IDR_PROFILE_AVATAR_26",
            "background_apps": False,
            "is_ephemeral": False,
            "is_using_default_avatar": True,
            "is_using_default_name": False,
            "name": profile.display_name,
        }
        local_state.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")

        # Also stabilise the per-profile Preferences so Chrome doesn't show "Profile may have
        # been used by another version" prompts.
        prefs_path = profile.path / "Preferences"
        if prefs_path.exists():
            try:
                prefs = json.loads(prefs_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                prefs = {}
            prefs.setdefault("profile", {})
            prefs["profile"]["name"] = profile.display_name
            prefs["profile"]["exit_type"] = "Normal"
            prefs["profile"]["is_using_default_name"] = False
            prefs_path.write_text(json.dumps(prefs, indent=2, sort_keys=True), encoding="utf-8")

        lock = profile.path / ".arc-exporter.json"
        lock.write_text(
            json.dumps(
                {
                    "tool": "arc-exporter",
                    "target": self.name,
                    "created_at": dt.datetime.now().isoformat(timespec="seconds"),
                    "display_name": profile.display_name,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    def import_passwords(
        self,
        arc_login_data: Path,
        target_profile: TargetProfile,
        *,
        arc_aes_key: bytes | None,
        target_aes_key: bytes,
        backups: BackupManager,
    ) -> int:
        """Re-encrypt Arc logins with the target's Safe Storage key and merge into the target DB."""
        if not arc_login_data.exists() or not target_aes_key:
            return 0
        import sqlite3

        target_db = target_profile.path / "Login Data"
        backups.back_up(target_db, description=f"{self.name} login data pre-migration")
        if not target_db.exists():
            # Chrome creates this file on first launch; create an empty schema if needed.
            target_db.parent.mkdir(parents=True, exist_ok=True)
        n = 0
        with sqlite3.connect(str(target_db)) as conn:
            self._ensure_logins_schema(conn)
            cols = [r[1] for r in conn.execute("PRAGMA table_info(logins)").fetchall()]
            now_us = _now_chromium_us()
            for row in iter_logins(arc_login_data):
                pw = ""
                if looks_like_v10(row.password_blob) and arc_aes_key is not None:
                    try:
                        pw = decrypt_v10(row.password_blob, arc_aes_key)
                    except CryptoError:
                        continue
                if not pw:
                    continue
                blob = encrypt_v10(pw, target_aes_key)
                realm = _realm_from_url(row.origin_url)
                conn.execute(
                    "DELETE FROM logins WHERE origin_url=? AND username_value=? AND signon_realm=?",
                    (row.origin_url, row.username, realm),
                )
                row_dict = {
                    "origin_url": row.origin_url,
                    "action_url": "",
                    "username_element": "",
                    "username_value": row.username,
                    "password_element": "",
                    "password_value": blob,
                    "submit_element": "",
                    "signon_realm": realm,
                    "date_created": now_us,
                    "date_last_used": now_us,
                    "date_password_modified": now_us,
                    "blacklisted_by_user": 0,
                    "scheme": 0,
                    "password_type": 0,
                    "times_used": 0,
                    "display_name": "",
                    "icon_url": "",
                    "federation_origin": "",
                    "skip_zero_click": 0,
                }
                use_cols = [c for c in row_dict if c in cols]
                conn.execute(
                    f"INSERT INTO logins ({', '.join(use_cols)}) VALUES ({', '.join(['?'] * len(use_cols))})",
                    [row_dict[c] for c in use_cols],
                )
                n += 1
            conn.commit()
        return n

    def import_cards(
        self,
        arc_web_data: Path,
        target_profile: TargetProfile,
        *,
        arc_aes_key: bytes | None,
        target_aes_key: bytes,
        backups: BackupManager,
    ) -> int:
        if not arc_web_data.exists() or not target_aes_key:
            return 0
        import sqlite3

        target_db = target_profile.path / "Web Data"
        backups.back_up(target_db, description=f"{self.name} web data pre-migration")
        target_db.parent.mkdir(parents=True, exist_ok=True)
        n = 0
        with sqlite3.connect(str(target_db)) as conn:
            self._ensure_cards_schema(conn)
            for c in iter_credit_cards(arc_web_data):
                pan = ""
                if looks_like_v10(c.card_number_encrypted) and arc_aes_key is not None:
                    try:
                        pan = decrypt_v10(c.card_number_encrypted, arc_aes_key)
                    except CryptoError:
                        continue
                if not pan:
                    continue
                blob = encrypt_v10(pan, target_aes_key)
                conn.execute(
                    "INSERT INTO credit_cards (name_on_card, expiration_month, expiration_year, "
                    "card_number_encrypted) VALUES (?, ?, ?, ?)",
                    (c.name_on_card, c.expiration_month, c.expiration_year, blob),
                )
                n += 1
            conn.commit()
        return n

    def migrate_profile(
        self,
        target_profile: TargetProfile,
        request: MigrationRequest,
    ) -> MigrationReport:
        """Run the full Chromium-family migration into ``target_profile``.

        Two execution paths:

        - **Full** (``request.source_profile`` is set): copy the Arc profile tree into
          a brand-new Chromium profile dir, register it in ``Local State``, merge
          ``Login Data`` / ``Web Data`` with re-encrypted credentials.
        - **Stash-only** (no ``source_profile``): drop the portable artefact files
          into ``Profile N/imports/`` for the user to click-through Chrome's import
          dialog. Used when the caller only has the portable exports.
        """
        report = MigrationReport(target=self.name, profile=target_profile.display_name)
        if request.dry_run:
            report.succeeded["bookmarks"] = 0
            return report

        if request.source_profile is not None and request.target_aes_key:
            return self._full_migration(target_profile, request, report)
        return self._stash_artefacts(target_profile, request, report)

    def _full_migration(
        self,
        target_profile: TargetProfile,
        request: MigrationRequest,
        report: MigrationReport,
    ) -> MigrationReport:
        from arc_exporter.guards.backups import BackupManager

        src = request.source_profile
        assert src is not None  # for mypy
        log.info(
            "[%s] full migration: %s -> %s",
            self.name,
            src.path,
            target_profile.path,
        )
        # 1) Copy the Arc profile into the already-allocated target profile dir.
        if target_profile.path.exists():
            shutil.rmtree(target_profile.path)
        skip: set[str] = set()
        if not request.keep_cache_dirs:
            skip |= _CACHE_SKIP
        if request.strip_storage:
            skip |= _STORAGE_DIRS
        log.debug("[%s] skip-dirs: %s", self.name, sorted(skip))
        final = safe_copy_tree(src.path, target_profile.path, skip=skip)
        log.info("[%s] profile tree copy complete -> %s", self.name, final)
        target_profile = TargetProfile(
            directory_name=final.name,
            display_name=target_profile.display_name,
            path=final,
        )
        self._register_profile(target_profile)
        report.profile = target_profile.display_name
        # Cookies/history/extensions ride along with the profile tree copy. Bookmarks
        # do *not*: Arc keeps them in the global StorableSidebar.json, so the per-
        # profile "Bookmarks" file we just copied is empty. Replace it with a Chrome-
        # native JSON we synthesize from the sidebar tree.
        try:
            from arc_exporter.export.bookmarks_chrome_json import write_chrome_bookmarks
            from arc_exporter.parsers.sidebar import load_sidebar

            if request.arc_sidebar_path and request.arc_sidebar_path.exists():
                sidebar_result = load_sidebar(request.arc_sidebar_path)
                profile_spaces = sidebar_result.for_profile(src.directory_name)
                n = write_chrome_bookmarks(profile_spaces, target_profile.path / "Bookmarks")
                report.succeeded["bookmarks"] = n
            else:
                report.succeeded["bookmarks"] = 0
        except Exception as e:
            report.errors["bookmarks"] = str(e)
        # History is plaintext (URLs, titles, visit counts) so the copy is sufficient.
        report.succeeded["history"] = 1
        report.succeeded["extensions"] = 1

        # Cookies need re-encryption: encrypted_value is v10-prefixed AES-CBC against
        # Arc's Safe Storage key. Without this pass the target browser sees opaque
        # bytes and treats every session cookie as missing — i.e. you're signed out
        # of every site.
        try:
            n_cookies = self._reencrypt_cookies(
                target_profile,
                arc_aes_key=request.arc_aes_key,
                target_aes_key=request.target_aes_key,
            )
            log.info("[%s] re-encrypted %d cookie(s)", self.name, n_cookies)
            report.succeeded["cookies"] = n_cookies
        except Exception as e:
            report.errors["cookies"] = str(e)

        # 2) Re-encrypt credentials. The profile-tree copy in (1) brought along the
        # Arc-encrypted Login Data / Web Data, which the target browser cannot decrypt
        # (different Safe Storage key). Wipe the copied rows and re-insert each one
        # encrypted with the target's key.
        backups = BackupManager(target_profile.path.parent / ".arc-exporter-backups")
        import sqlite3

        login_db = target_profile.path / "Login Data"
        if login_db.exists():
            with sqlite3.connect(str(login_db)) as conn:
                conn.execute("DELETE FROM logins")
                conn.commit()
        web_db = target_profile.path / "Web Data"
        if web_db.exists():
            with sqlite3.connect(str(web_db)) as conn:
                conn.execute("DELETE FROM credit_cards")
                conn.commit()
        if request.target_aes_key:
            try:
                n = self.import_passwords(
                    src.login_data,
                    target_profile,
                    arc_aes_key=request.arc_aes_key,
                    target_aes_key=request.target_aes_key,
                    backups=backups,
                )
                log.info("[%s] re-encrypted %d password(s)", self.name, n)
                report.succeeded["passwords"] = n
            except Exception as e:
                report.errors["passwords"] = str(e)
            try:
                n = self.import_cards(
                    src.web_data,
                    target_profile,
                    arc_aes_key=request.arc_aes_key,
                    target_aes_key=request.target_aes_key,
                    backups=backups,
                )
                log.info("[%s] re-encrypted %d credit card(s)", self.name, n)
                report.succeeded["cards"] = n
            except Exception as e:
                report.errors["cards"] = str(e)
        else:
            log.warning(
                "[%s] no Safe Storage key for target — credentials cannot be merged. "
                "Launch %s once so it creates its keychain entry, then re-run.",
                self.name,
                self.name.title(),
            )
            report.skipped["passwords"] = "no target Safe Storage key"
            report.skipped["cards"] = "no target Safe Storage key"
        return report

    def _reencrypt_cookies(
        self,
        target_profile: TargetProfile,
        *,
        arc_aes_key: bytes | None,
        target_aes_key: bytes | None,
    ) -> int:
        """Re-encrypt every ``v10``-prefixed cookie in-place against ``target_aes_key``.

        Cookies were copied from Arc with Arc-encrypted ``encrypted_value`` blobs. The
        target browser uses a different ``Safe Storage`` key and would silently treat
        every cookie as undecodable on first read. We rewrite each blob; rows we can't
        decrypt (e.g. ``v20`` app-bound encryption on Windows, future versions) are
        left untouched.

        Returns the count of successfully re-encrypted rows.
        """
        import sqlite3

        db = target_profile.path / "Cookies"
        if not db.exists() or arc_aes_key is None or target_aes_key is None:
            return 0
        rewritten = 0
        failed = 0
        with sqlite3.connect(str(db)) as conn:
            conn.text_factory = bytes
            cur = conn.execute("SELECT rowid, encrypted_value FROM cookies")
            updates: list[tuple[bytes, int]] = []
            for rowid, ev in cur.fetchall():
                if not ev or not looks_like_v10(ev):
                    continue
                try:
                    plaintext = decrypt_v10(ev, arc_aes_key)
                except CryptoError:
                    failed += 1
                    continue
                try:
                    blob = encrypt_v10(plaintext, target_aes_key)
                except Exception:
                    failed += 1
                    continue
                updates.append((blob, rowid))
            if updates:
                conn.executemany("UPDATE cookies SET encrypted_value = ? WHERE rowid = ?", updates)
                conn.commit()
                rewritten = len(updates)
        return rewritten

    def _stash_artefacts(
        self,
        target_profile: TargetProfile,
        request: MigrationRequest,
        report: MigrationReport,
    ) -> MigrationReport:
        for kind, src in request.artefact_paths.items():
            if kind not in self.supports:
                report.skipped[kind] = "not supported by this target"
                continue
            if not src.exists():
                report.skipped[kind] = f"file missing: {src}"
                continue
            try:
                if kind == "bookmarks":
                    self._import_bookmarks_html(src, target_profile)
                elif kind == "passwords":
                    self._stash_password_csv(src, target_profile)
                elif kind == "cards":
                    self._stash_cards_csv(src, target_profile)
                elif kind == "cookies":
                    self._stash_cookies(src, target_profile)
                elif kind == "extensions":
                    self._stash_extensions_report(src, target_profile)
                report.succeeded[kind] = 1
            except Exception as e:
                report.errors[kind] = str(e)
        return report

    def _import_bookmarks_html(self, src: Path, target_profile: TargetProfile) -> None:
        """Drop the NETSCAPE HTML next to the target profile so Chrome's import dialog finds it.

        Programmatic merge into the binary ``Bookmarks`` JSON is intentionally avoided —
        the user-facing import UX is much more reliable.
        """
        dst = target_profile.path / "imports" / src.name
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

    def _stash_password_csv(self, src: Path, target_profile: TargetProfile) -> None:
        dst = target_profile.path / "imports" / src.name
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

    def _stash_cards_csv(self, src: Path, target_profile: TargetProfile) -> None:
        dst = target_profile.path / "imports" / src.name
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

    def _stash_cookies(self, src: Path, target_profile: TargetProfile) -> None:
        dst = target_profile.path / "imports" / src.name
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

    def _stash_extensions_report(self, src: Path, target_profile: TargetProfile) -> None:
        dst = target_profile.path / "imports" / src.name
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

    @staticmethod
    def _ensure_logins_schema(conn) -> None:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS logins ("
            "origin_url TEXT NOT NULL, action_url TEXT, username_element TEXT, "
            "username_value TEXT, password_element TEXT, password_value BLOB, "
            "submit_element TEXT, signon_realm TEXT NOT NULL, date_created INTEGER NOT NULL, "
            "blacklisted_by_user INTEGER NOT NULL, scheme INTEGER NOT NULL, "
            "password_type INTEGER, times_used INTEGER, "
            "display_name TEXT, icon_url TEXT, federation_origin TEXT, "
            "skip_zero_click INTEGER, "
            "date_last_used INTEGER, date_password_modified INTEGER"
            ")"
        )

    @staticmethod
    def _ensure_cards_schema(conn) -> None:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS credit_cards ("
            "name_on_card TEXT, expiration_month INTEGER, "
            "expiration_year INTEGER, card_number_encrypted BLOB"
            ")"
        )


def _realm_from_url(url: str) -> str:
    from urllib.parse import urlparse

    try:
        u = urlparse(url)
        if u.scheme and u.netloc:
            return f"{u.scheme}://{u.netloc}"
    except ValueError:
        pass
    return url


def _now_chromium_us() -> int:
    import time as _time

    return int((_time.time() + 11644473600) * 1_000_000)
