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
    # ``Sessions/`` is Chrome's tab/window restoration store. We deliberately
    # never carry Arc's tab session over: arc-exporter takes the user's
    # Arc-pinned + today-tabs and opens THOSE as Chrome tabs in phase 2.
    # If we copy Sessions/, Chrome on its first launch eagerly restores
    # every URL Arc had open at quit-time (often 50+ tabs of random
    # browsing), drowning out the curated tab list we wanted to present.
    # Same reasoning for the root-level ``Current Session`` / ``Current Tabs``
    # / ``Last Session`` / ``Last Tabs`` files; those are cleaned in
    # ``_clean_session_artifacts`` after the profile-tree copy.
    "Sessions",
}

# Root-level session/restoration files that, like ``Sessions/``, would
# cause Chrome to restore Arc's old tab state instead of the curated
# pinned-tab list we want to surface. Cleaned post-copy so we don't have
# to teach ``safe_copy_tree`` to skip individual files.
_SESSION_ARTIFACTS = (
    "Current Session",
    "Current Tabs",
    "Last Session",
    "Last Tabs",
)

# Site/PWA storage. Skipping these breaks signed-in sessions; off by default in the
# new code (legacy stripped them unconditionally). User can opt in via --strip-storage.
_STORAGE_DIRS = {
    "IndexedDB",
    "Local Storage",
    "Session Storage",
    "Storage",
    "File System",
}

# Extension binaries. We never copy Arc's ``Extensions/<id>/<version>/`` folders:
# Chromium's content-verification subsystem hashes every file in each extension
# and compares against the signed ``_metadata/verified_contents.json`` shipped
# by the Web Store. Arc ships patched / older versions for several extensions,
# so the on-disk hashes diverge from Google's published values and the target
# browser flags every transferred extension as ``DISABLE_CORRUPTED`` on launch.
# Instead, ``ChromiumTarget.migrate_extensions`` enumerates the extensions out
# of Arc's ``Secure Preferences``, writes one ``External Extensions/<id>.json``
# descriptor per extension pointing at the Web Store update URL, and briefly
# launches the target browser so it pulls fresh Google-signed CRX bundles
# straight into ``Extensions/`` — those pass content verification cleanly.
# The user's per-extension storage (``Local Extension Settings``, ``Extension
# State``, ``Sync Extension Settings``, ``Extension Rules``, …) still rides
# along with the profile-tree copy, so settings carry over once the fresh
# binaries load.
_EXTENSION_BINARIES = {"Extensions"}


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
        skip: set[str] = set(_EXTENSION_BINARIES)
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
        _clean_session_artifacts(target_profile.path)
        self._register_profile(target_profile)
        report.profile = target_profile.display_name
        # Cookies/history ride along with the profile tree copy. Bookmarks do *not*:
        # Arc keeps them in the global StorableSidebar.json, so the per-profile
        # "Bookmarks" file we just copied is empty. Replace it with a Chrome-native
        # JSON we synthesize from the sidebar tree. Extensions are handled below
        # via External Extensions descriptors — copying them was wiped out by
        # Chrome's Secure Preferences HMAC check.
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

        # Extensions + tab restore go LAST: we launch the target browser
        # twice — once briefly to install Web Store extensions, then again
        # for the user with their tabs on the command line — and both
        # launches grab an exclusive lock on Login Data / Web Data /
        # Cookies. Anything that touches those DBs has to land before this.
        try:
            self.migrate_extensions_and_tabs(src, target_profile, request, report)
        except Exception as e:
            report.errors["extensions"] = str(e)
            log.exception("[%s] extension + tab migration failed: %s", self.name, e)
        return report

    def migrate_extensions_and_tabs(
        self,
        source_profile,
        target_profile: TargetProfile,
        request: MigrationRequest,
        report: MigrationReport,
    ) -> None:
        """Two-phase Chrome bootstrap: install extensions, then open tabs.

        Why two phases instead of one nicer single-launch:

        - Web Store installs land in ``state=0`` (sideload protection).
          The fix — flipping ``state=1`` and resigning Secure Preferences —
          can only be done while Chrome is NOT running, because Chrome
          rewrites Secure Preferences on shutdown and would overwrite our
          edit. So we SIGTERM after phase 1, do the resign, then relaunch.
        - The user asked for Chrome to stay open with their tabs ready, so
          phase 2 is a detached relaunch with pinned + today-tab URLs as
          command-line arguments. We don't terminate that process.

        What we CAN'T do, despite the previous attempt:

        - Pin tabs / put tabs into groups: Chrome 142+ removed every
          external escape hatch for ``chrome.tabs.update({pinned:true})``
          and ``chrome.tabGroups`` — ``--load-extension`` is silently
          ignored, ``Extensions.loadUnpacked`` was removed from CDP, and
          local CRX install is blocked on macOS. The only remaining
          mechanism is publishing our own Web Store extension, which isn't
          worth it for a one-shot migration tool.

        Records ``succeeded["extensions"]`` and ``succeeded["tabs"]``.
        """
        from arc_exporter.targets.external_extensions import (
            install_extensions_for_profile,
            launch_chrome_with_tabs,
            macos_app_binary,
        )
        from arc_exporter.targets.secure_prefs import resign_in_place

        wanted = _arc_webstore_extension_ids(source_profile.path)
        urls = _build_tab_urls(source_profile, request)
        # ``target_aes_key`` is the destination browser's Safe Storage key
        # (PBKDF2 of the keychain password). We need it to compute the
        # Chrome 137+ ``_encrypted_hash`` siblings inside Secure Preferences
        # — without those, Chrome wipes every entry we touched on next
        # launch even though the legacy HMACs are correct. This was the
        # post-migration "0 extensions" regression seen on macOS Chrome 148.
        target_key = request.target_aes_key

        # Strip Arc's stale extension state from the copied Preferences /
        # Secure Preferences and resign against the target's HMAC seed. We
        # do this BEFORE phase 1 so Chrome doesn't see ghost extension
        # paths and refuse to launch.
        secure_prefs_path = target_profile.path / "Secure Preferences"
        prefs_path = target_profile.path / "Preferences"
        for path in (secure_prefs_path, prefs_path):
            if not path.exists():
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as e:
                log.warning("[%s] could not read %s: %s", self.name, path.name, e)
                continue
            _strip_extension_state(data)
            resign_in_place(self.name, data, target_aes_key=target_key)
            path.write_text(
                json.dumps(data, separators=(",", ":"), ensure_ascii=False),
                encoding="utf-8",
            )
        log.info("[%s] pre-launch prefs sanitized + resigned", self.name)

        binary = macos_app_binary(self.process)
        if binary is None:
            if wanted:
                report.skipped["extensions"] = (
                    f"{self.name} executable not found on this OS; install manually from the HTML report"
                )
            if urls:
                report.skipped["tabs"] = (
                    f"{self.name} executable not found; cannot restore tabs"
                )
            return

        if not wanted and not urls:
            report.succeeded["extensions"] = 0
            report.succeeded["tabs"] = 0
            return

        # -- Phase 1: install Web Store extensions, briefly. -----------------
        installed: list[str] = []
        missed: list[str] = []
        if wanted:
            installed, missed = install_extensions_for_profile(
                extension_ids=wanted,
                target_profile_path=target_profile.path,
                browser_binary=binary,
                external_extensions_dir=self.root_dir / "External Extensions",
                timeout_s=300.0,
                profile_display_name=target_profile.display_name,
            )
            log.info(
                "[%s] phase 1: installed %d/%d Web Store extensions",
                self.name,
                len(installed),
                len(wanted),
            )

        # -- Between phases: auto-enable, set session restore, resign. -------
        # Chrome marks External-Extensions-installed entries with
        # ``state=DISABLED_USER_ACTION`` and disable_reasons=[5]. Flip
        # them to enabled BEFORE phase 2 so the user opens Chrome and sees
        # working extensions instead of a wall of "Enable" prompts.
        enabled = _auto_enable_extensions(
            self.name, target_profile.path, installed, target_aes_key=target_key
        )
        log.info(
            "[%s] auto-enabled %d/%d freshly-installed extension(s)",
            self.name,
            enabled,
            len(installed),
        )
        # Force ``session.restore_on_startup = 1`` while Chrome is OFF so
        # the next user-initiated Chrome launch restores whatever tabs
        # phase 2 leaves open. Chrome would clobber this if we wrote it
        # mid-run.
        if prefs_path.exists():
            try:
                data = json.loads(prefs_path.read_text(encoding="utf-8"))
                _set_session_restore_continue(data)
                resign_in_place(self.name, data, target_aes_key=target_key)
                prefs_path.write_text(
                    json.dumps(data, separators=(",", ":"), ensure_ascii=False),
                    encoding="utf-8",
                )
            except (OSError, json.JSONDecodeError) as e:
                log.warning("[%s] could not set session restore: %s", self.name, e)

        # -- Phase 2: open Chrome for the user with their tabs. --------------
        opened = 0
        if urls:
            opened = launch_chrome_with_tabs(
                target_profile_path=target_profile.path,
                browser_binary=binary,
                urls=urls,
                profile_display_name=target_profile.display_name,
            )
            log.info(
                "[%s] phase 2: launched Chrome with %d tab(s), left running",
                self.name,
                opened,
            )

        report.succeeded["extensions"] = len(installed)
        report.succeeded["tabs"] = opened
        if missed:
            report.notes["extensions"] = (
                f"{len(missed)} extension(s) didn't auto-install (most likely "
                f"removed from the Web Store): {', '.join(missed[:3])}"
                f"{'…' if len(missed) > 3 else ''}. See the HTML report for "
                "direct links."
            )
        if urls:
            report.notes["tabs"] = (
                "Tabs are open as ordinary (un-pinned) tabs. Chrome 142+ removed "
                "the API third-party tools use to pin tabs or create tab groups, "
                "so pin / group state can't be reproduced automatically — "
                "right-click any tab → 'Pin tab' if you want them back."
            )

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


def _arc_webstore_extension_ids(arc_profile_path: Path) -> list[str]:
    """Pull Web-Store-installable extension IDs out of Arc's ``Secure Preferences``.

    Filters out anything that isn't a normal Web Store extension:

    - Chromium component extensions (``location=4``) ship with the browser
      itself, so there's nothing for us to install. Arc, the Web Store
      launcher itself, the in-browser PDF viewer, and Hangouts all fall in
      this bucket — they show ``from_webstore=false`` and have no
      ``update_url`` because they're not delivered through the Web Store.
    - Force-installed enterprise policy extensions (``location=6`` / ``8``)
      need the matching admin policy to be present on the target machine;
      without it the target browser would refuse the install anyway.
    - Unpacked / developer extensions (``location=3``) live only on the
      user's disk; there's no Web Store entry to redeliver them from.

    The result is the set of extensions that pass both
    ``from_webstore=true`` AND a Web Store update URL — anything Google
    actually distributes through ``clients2.google.com``. Everything else
    is left to the HTML report's manual-reinstall fallback.
    """
    sp_path = arc_profile_path / "Secure Preferences"
    if not sp_path.exists():
        return []
    try:
        data = json.loads(sp_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    settings = (data.get("extensions") or {}).get("settings") or {}
    out: list[str] = []
    for ext_id, meta in settings.items():
        if not (isinstance(ext_id, str) and len(ext_id) == 32 and ext_id.isalpha() and ext_id.islower()):
            continue
        if not isinstance(meta, dict):
            continue
        location = meta.get("location")
        if location not in (1, 5):  # INTERNAL or EXTERNAL_PREF_DOWNLOAD = Web Store
            continue
        # Chrome's own internal "extensions" (Web Store launcher, PDF viewer,
        # Hangouts, plus anything Arc bolted on for its own UI) all show
        # ``from_webstore=false``; without this guard they'd appear in the
        # "didn't auto-install" warning every single run.
        if meta.get("from_webstore") is not True:
            continue
        manifest = meta.get("manifest") or {}
        update_url = manifest.get("update_url") if isinstance(manifest, dict) else None
        if update_url and "clients2.google.com" not in update_url:
            continue
        out.append(ext_id)
    return sorted(set(out))


def _auto_enable_extensions(
    target_name: str,
    target_profile_path: Path,
    extension_ids: list[str],
    *,
    target_aes_key: bytes | None = None,
) -> int:
    """Best-effort pre-launch enable pass.

    Chrome 142+ enforces an unavoidable side-load protection: any extension
    Chrome installed via the External Extensions descriptor mechanism
    lives in ``location=6 (EXTERNAL_PREF_DOWNLOAD)`` and gets
    ``disable_reasons=[8192]`` (``DISABLE_EXTERNAL_EXTENSION``). When
    Chrome launches it re-applies this state on every read — flipping
    ``state=1`` here is overwritten before the user sees a window, and
    promoting to ``location=1`` is demoted back to 6 if the descriptor
    file still exists (which it must, or Chrome's garbage collector
    deletes the extension entirely on next launch).
    See: empirical bisection log dated 2026-05-16 against Chrome 148.0.7778.

    We still write the "intended" state (enabled, ``location=1``, default
    flags cleared) for two reasons:

    * Older Chromium forks (pre-142, plus Brave/Edge/Opera) honour the
      ``state=1`` clear because their side-load protection is weaker.
      Promoting + enabling there gets the extensions in front of the
      user with zero clicks.
    * The resigned MACs cover Chrome's tamper detection, so the
      "EnforcementLevel" trackers don't reset *other* prefs (theme,
      homepage, search engine) just because we changed an extension
      entry.

    On Chrome 142+ the practical outcome is: extensions show up disabled,
    user clicks Enable in the popup that Chrome itself surfaces. The CLI
    Next Steps panel calls this out so the user isn't surprised.

    Returns the count of extensions whose entries we touched.
    """
    if not extension_ids:
        return 0
    from arc_exporter.targets.secure_prefs import resign_in_place

    secure_prefs_path = target_profile_path / "Secure Preferences"
    if not secure_prefs_path.exists():
        return 0
    try:
        data = json.loads(secure_prefs_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0
    settings = (data.get("extensions") or {}).get("settings") or {}
    enabled = 0
    for ext_id in extension_ids:
        meta = settings.get(ext_id)
        if not isinstance(meta, dict):
            continue
        meta["state"] = 1
        meta["disable_reasons"] = []
        meta["location"] = 1
        meta["was_installed_by_default"] = False
        meta["was_installed_by_oem"] = False
        enabled += 1
    if enabled == 0:
        return 0
    resign_in_place(target_name, data, target_aes_key=target_aes_key)
    secure_prefs_path.write_text(
        json.dumps(data, separators=(",", ":"), ensure_ascii=False),
        encoding="utf-8",
    )
    return enabled


def _strip_extension_state(prefs: dict) -> None:
    """Remove per-extension settings from a Preferences / Secure Preferences dict.

    Leaves the rest of the tree (search engines, profile metadata, …) intact
    so the subsequent ``resign_in_place`` pass still has tracked prefs to
    cover. Also clears the matching ``protection.macs.extensions.settings``
    leaves so the resigner doesn't produce signatures for non-existent
    entries that Chromium would later flag as missing.
    """
    extensions = prefs.get("extensions")
    if isinstance(extensions, dict):
        extensions.pop("settings", None)
        extensions.pop("install_signature", None)
        extensions.pop("pending_updates", None)
    macs_root = (prefs.get("protection") or {}).get("macs") or {}
    if isinstance(macs_root, dict):
        ext_macs = macs_root.get("extensions")
        if isinstance(ext_macs, dict):
            ext_macs.pop("settings", None)
            ext_macs.pop("install_signature", None)


def _clean_session_artifacts(profile_path: Path) -> None:
    """Remove the root-level session files we couldn't filter out at copy time.

    ``safe_copy_tree`` skips directories by name (``Sessions/`` is in
    :data:`_CACHE_SKIP`) but copies every file under the profile root
    unconditionally. Chrome stores the user's "what should I restore on
    next launch?" state in four sibling files at the profile root:
    ``Current Session``, ``Current Tabs``, ``Last Session``, ``Last Tabs``.

    If we leave Arc's copies of those files in place, Chrome's session
    restore subsystem kicks in on the very first launch — including
    phase 1's near-silent extension-install launch — and reopens every
    URL Arc had loaded at quit time. That clobbers the 17-or-so curated
    pinned/today-tabs we'd otherwise present in phase 2.

    Idempotent: missing files are silently ignored. We don't touch the
    ``Sessions/`` directory here because the copy step already skipped
    it; this function is just for the loose root-level remnants.
    """
    for name in _SESSION_ARTIFACTS:
        p = profile_path / name
        try:
            if p.is_file():
                p.unlink()
            elif p.is_dir():
                shutil.rmtree(p)
        except OSError as e:
            log.debug("could not remove %s: %s", p, e)


def _set_session_restore_continue(prefs: dict) -> None:
    """Set ``session.restore_on_startup = 1`` ("Continue where you left off").

    Chrome's enum (``chrome/browser/prefs/session_startup_pref.h``):

    - ``0``: open last session, but only for incognito (deprecated for normal)
    - ``1``: continue where you left off (restore previous session) ← we want this
    - ``4``: open new tab page (Chrome's default for fresh profiles)
    - ``5``: open a fixed list of URLs

    Setting this is the difference between "tabs come back when I launch
    Chrome tomorrow" and "Chrome opens a clean NTP and the bootstrap tabs
    are silently lost". The pref itself isn't HMAC-tracked, but it lives in
    Preferences alongside other things that are, so we set it BEFORE the
    resign step so the rest of the file is still self-consistent.
    """
    session = prefs.setdefault("session", {})
    if isinstance(session, dict):
        session["restore_on_startup"] = 1
        session.pop("startup_urls", None)


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


def _build_tab_urls(source_profile, request: MigrationRequest) -> list[str]:
    """Flatten Arc's pinned + today-tab trees into a single ordered URL list.

    Order matters: pinned URLs are prepended so they end up leftmost in
    Chrome's tab strip — which is where Chrome convention puts pinned tabs
    even though we can't programmatically set the pinned flag. That at
    least keeps the visual layout close to what Arc looked like, and makes
    "right-click → Pin" trivial for the user.

    Returns an empty list if the request doesn't carry a sidebar path or
    the sidebar parse fails.
    """
    if not request.arc_sidebar_path or not request.arc_sidebar_path.exists():
        return []
    try:
        from arc_exporter.parsers.sidebar import load_sidebar
    except ImportError:
        return []
    try:
        sidebar = load_sidebar(request.arc_sidebar_path)
    except Exception as e:
        log.warning("could not parse sidebar for tab URLs: %s", e)
        return []
    spaces = sidebar.for_profile(source_profile.directory_name) or []
    pinned_urls: list[str] = []
    today_urls: list[str] = []
    for sp in spaces:
        for node in sp.pinned:
            pinned_urls.extend(_walk_bookmark_urls(node))
        for node in sp.today_tabs:
            today_urls.extend(_walk_bookmark_urls(node))

    # Dedupe while preserving order; many users have the same site pinned
    # AND in today-tabs after a long session and we don't want them to see
    # 4 copies of github.com.
    seen: set[str] = set()
    out: list[str] = []
    for u in pinned_urls + today_urls:
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _walk_bookmark_urls(node) -> list[str]:
    """Depth-first traversal yielding every leaf URL under a BookmarkNode."""
    if getattr(node, "kind", None) == "bookmark":
        url = getattr(node, "url", None)
        return [url] if url else []
    urls: list[str] = []
    for child in getattr(node, "children", None) or []:
        urls.extend(_walk_bookmark_urls(child))
    return urls
