import argparse
import difflib
import csv
import datetime as dt
import glob
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
import time
import threading
from pathlib import Path
from az.paths import *
from az.utils import ensure, safe_dir_name, read_json, write_json_atomic
from az.bookmarks import export_pinned_bookmarks

# ---------- Paths (macOS) ----------
HOME = Path.home()
NOW = dt.datetime.now().strftime("%Y%m%d-%H%M%S")

ARC_ROOT        = HOME / "Library/Application Support/Arc"
ARC_USER_DATA   = ARC_ROOT / "User Data"
ARC_LOCAL_STATE = ARC_USER_DATA / "Local State"
ARC_SIDEBAR     = ARC_ROOT / "StorableSidebar.json"  # bookmarks/pinned source

CHROME_ROOT        = HOME / "Library/Application Support/Google/Chrome"
CHROME_LOCAL_STATE = CHROME_ROOT / "Local State"

ZEN_CANDIDATES = [
    "/Applications/Zen Browser.app",
    "/Applications/Zen.app",
]

# Outputs (write inside repo root; paths are ignored by .gitignore)
BASE_DIR = Path(__file__).resolve().parent
OUT_ROOT = BASE_DIR / "arc-export"
PROFILES_DIR = OUT_ROOT / "profiles"

# AMO API + install URL
AMO_API = "https://addons.mozilla.org/api/v5"
AMO_BROWSER_MAPPINGS = f"{AMO_API}/addons/browser-mappings/?browser=chrome"
AMO_SEARCH = f"{AMO_API}/addons/search/"
AMO_DETAIL = f"{AMO_API}/addons/addon"
AMO_LATEST_XPI = "https://addons.mozilla.org/firefox/downloads/latest/{slug}/latest.xpi"

# Copy-time skips (huge/cached dirs)
SKIP_DIRS = {"Cache", "Code Cache", "GPUCache", "Crashpad", "ShaderCache",
             "Service Worker", "Optimization Hints", "GrShaderCache",
             "Network Action Predictor", "Platform Notifications",
             "Reporting and NEL", "Top Sites-journal", "Visited Links",
             # Heavy site data directories that can balloon sizes
             "IndexedDB", "Local Storage", "Session Storage", "Storage",
             "File System", "Media Cache"}
             # Note: NOT skipping "History", "Web Data", "Login Data", "Cookies" - these contain user data


VERBOSE = False
def log(msg, lvl="*"):
    if VERBOSE:
        print(f"[{lvl}] {msg}")

def print_progress(current_index: int, total_count: int, message: str = ""):
    width = 30
    done = int(width * current_index / max(total_count, 1))
    bar = "#" * done + "-" * (width - done)
    suffix = f" {message}" if message else ""
    sys.stdout.write(f"\r[{bar}] {current_index}/{total_count}{suffix}")
    sys.stdout.flush()

def ensure(p: Path):
    p.mkdir(parents=True, exist_ok=True)
    return p

def safe_dir_name(name: str) -> str:
    s = name.strip() if isinstance(name, str) else "profile"
    # Replace problematic characters with '-'
    s = re.sub(r"[\\/:*?\"<>|]+", "-", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s or "profile"

# ---------- Utilities ----------
def arc_profiles():
    """
    Get list of Arc profiles, excluding the system profile.
    Filters by both directory name and display name.
    """
    if not ARC_USER_DATA.is_dir():
        sys.exit(f"Arc not found at: {ARC_USER_DATA}")

    # First, get the display names to filter by both name and display name
    ls = read_json(ARC_LOCAL_STATE)
    ic = (ls.get("profile") or {}).get("info_cache") or {}

    # Identify system profiles by either directory name or display name
    system_profiles = set()
    for k, meta in ic.items():
        if k == "__ARC_SYSTEM_PROFILE":
            system_profiles.add(k)
        if isinstance(meta, dict) and meta.get("name") == "__ARC_SYSTEM_PROFILE":
            system_profiles.add(k)

    # Now find the profiles that aren't system profiles
    profs = []
    for d in sorted(ARC_USER_DATA.iterdir()):
        if (d.is_dir() and
            (d / "Preferences").exists() and
            d.name not in system_profiles):
            profs.append(d)

    if not profs:
        sys.exit("No Arc profiles found.")
    return profs

def read_json(path: Path):
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def write_json_atomic(path: Path, obj: dict, do_backup=True):
    tmp = path.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, sort_keys=True)
    if do_backup and path.exists():
        bak = path.with_suffix(f".bak-{NOW}")
        try:
            shutil.copy2(path, bak)
            log(f"Backed up {path.name} → {bak.name}", "OK")
        except Exception as e:
            log(f"Backup failed for {path}: {e}", "!")
    tmp.replace(path)

# ---------- Arc names ----------
def arc_display_names():
    ls = read_json(ARC_LOCAL_STATE)
    ic = (ls.get("profile") or {}).get("info_cache") or {}
    out = {}
    for k, meta in ic.items():
        nm = meta.get("name") if isinstance(meta, dict) else None
        out[k] = nm or k
    return out

# ---------- Chrome Profile Monitoring ----------
class ChromeProfileMonitor:
    def __init__(self):
        self.monitoring = False
        self.monitor_thread = None
        self.log_file = Path("chrome_monitor.log")
        self.last_state = {}

    def start_monitoring(self):
        """Start monitoring Chrome profiles in a separate thread"""
        if self.monitoring:
            return

        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        log("Started Chrome profile monitoring", "OK")

    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1)
        log("Stopped Chrome profile monitoring", "OK")

    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                self._check_profile_state()
                time.sleep(2)  # Check every 2 seconds
            except Exception as e:
                self._log(f"Monitor error: {e}")
                time.sleep(5)

    def _check_profile_state(self):
        """Check current state of Chrome profiles"""
        current_state = self._get_current_state()

        # Compare with last state
        if self.last_state:
            self._detect_changes(self.last_state, current_state)

        self.last_state = current_state

    def _get_current_state(self):
        """Get current state of Chrome profiles"""
        state = {
            'profiles': {},
            'local_state': {},
            'timestamp': time.time()
        }

        # Check profile directories
        chrome_root = Path.home() / 'Library/Application Support/Google/Chrome'
        if chrome_root.exists():
            for item in chrome_root.iterdir():
                if item.is_dir() and item.name.startswith('Profile '):
                    profile_name = item.name  # Keep full name like "Profile 20", "Profile 18", etc.
                    state['profiles'][profile_name] = {
                        'exists': True,
                        'size': sum(f.stat().st_size for f in item.rglob('*') if f.is_file()),
                        'files': len(list(item.rglob('*'))),
                        'data_files': self._check_data_files(item)
                    }

        # Check Local State
        local_state_path = chrome_root / 'Local State'
        if local_state_path.exists():
            try:
                with open(local_state_path, 'r') as f:
                    local_state = json.load(f)
                state['local_state'] = local_state.get('profile', {}).get('info_cache', {})
            except Exception as e:
                state['local_state'] = {'error': str(e)}

        return state

    def _check_data_files(self, profile_dir):
        """Check if critical data files exist"""
        data_files = ['History', 'Web Data', 'Login Data', 'Cookies', 'Preferences']
        result = {}
        for file_name in data_files:
            file_path = profile_dir / file_name
            result[file_name] = {
                'exists': file_path.exists(),
                'size': file_path.stat().st_size if file_path.exists() else 0
            }
        return result

    def _detect_changes(self, old_state, new_state):
        """Detect changes between states"""
        # Check for deleted profiles
        old_profiles = set(old_state['profiles'].keys())
        new_profiles = set(new_state['profiles'].keys())

        deleted = old_profiles - new_profiles
        created = new_profiles - old_profiles

        if deleted:
            self._log(f"🚨 PROFILES DELETED: {deleted}")
            for profile in deleted:
                self._log(f"  Profile {profile} was deleted!")

        if created:
            self._log(f"📁 PROFILES CREATED: {created}")

        # Check for Local State changes
        old_local = old_state.get('local_state', {})
        new_local = new_state.get('local_state', {})

        if old_local != new_local:
            self._log(f"🔄 LOCAL STATE CHANGED")
            old_keys = set(old_local.keys())
            new_keys = set(new_local.keys())

            removed_keys = old_keys - new_keys
            added_keys = new_keys - old_keys

            if removed_keys:
                self._log(f"  Removed from Local State: {removed_keys}")
            if added_keys:
                self._log(f"  Added to Local State: {added_keys}")

    def _log(self, message):
        """Log message to file and console"""
        timestamp = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] {message}"

        # Log to file
        with open(self.log_file, 'a') as f:
            f.write(log_message + '\n')

        # Log to console only when verbose
        if VERBOSE:
            print(f"🔍 MONITOR: {message}")

    def get_monitor_log(self):
        """Get the monitoring log"""
        if self.log_file.exists():
            return self.log_file.read_text()
        return "No monitoring log found"

# Global monitor instance
chrome_monitor = ChromeProfileMonitor()

# ---------- Chrome profile mapping (non-destructive) ----------
def next_free_chrome_profile():
    used = set()
    if CHROME_ROOT.exists():
        for d in CHROME_ROOT.iterdir():
            m = re.fullmatch(r"Profile (\d+)", d.name)
            if m:
                used.add(int(m.group(1)))
    # Start from a higher number to avoid conflicts with existing profiles
    n = 20
    while n in used:
        n += 1
    log(f"Allocating Chrome profile number: {n}", "OK")
    return f"Profile {n}"

def copy_profile_safely(src: Path, dst: Path):
    if dst.exists():
        base = dst.name
        i = 2
        while (dst.parent / f"{base} ({i})").exists():
            i += 1
        dst = dst.parent / f"{base} ({i})"
    log(f"Copying Arc:{src.name} → Chrome:{dst.name} (skipping caches)")

    def ignore(dir_path, names):
        # Log what we're skipping for debugging
        skipped = {n for n in names if n in SKIP_DIRS}
        if skipped:
            log(f"Skipping in {dir_path}: {', '.join(skipped)}", "!")
        return skipped

    shutil.copytree(src, dst, symlinks=True, ignore=ignore)

    # Verify what was actually copied
    copied_files = []
    for data_file in ["History", "Web Data", "Login Data", "Cookies", "Preferences"]:
        if (dst / data_file).exists():
            size = (dst / data_file).stat().st_size
            copied_files.append(f"{data_file}({size:,}b)")
    log(f"Copied to {dst.name}: {', '.join(copied_files) if copied_files else 'NO DATA FILES'}", "OK")

    return dst

def register_chrome_profile(dir_name: str, display_name: str):
    ensure(CHROME_ROOT)
    ls = read_json(CHROME_LOCAL_STATE)
    ls.setdefault("profile", {})
    ls["profile"].setdefault("info_cache", {})

    # Create a more robust profile configuration that Chrome is less likely to reject
    meta = {
        "active_time": 0.0,
        "avatar_icon": "chrome://theme/IDR_PROFILE_AVATAR_26",
        "background_apps": False,
        "default_avatar_fill_color": -14737376,
        "default_avatar_stroke_color": -3684409,
        "enterprise_label": "",
        "force_signin_profile_locked": False,
        "gaia_given_name": "",
        "gaia_id": "",
        "gaia_name": "",
        "hosted_domain": "",
        "is_consented_primary_account": False,
        "is_ephemeral": False,  # CRITICAL: Prevent Chrome from treating as temporary
        "is_glic_eligible": False,
        "is_managed": 0,
        "is_using_default_avatar": True,
        "is_using_default_name": False,  # CRITICAL: We're providing a custom name
        "managed_user_id": "",
        "metrics_bucket_index": 153,
        "name": display_name,
        "profile_color_seed": -5715974,
        "profile_highlight_color": -14737376,
        "signin.with_credential_provider": False,
        "user_name": "",
    }

    ls["profile"]["info_cache"][dir_name] = meta

    # Also update the last_used and last_active_profiles to make Chrome recognize this profile
    ls["profile"]["last_used"] = dir_name
    ls["profile"]["last_active_profiles"] = [dir_name]

    write_json_atomic(CHROME_LOCAL_STATE, ls, do_backup=True)

    # Also ensure the profile's Preferences file has proper structure
    profile_prefs_path = CHROME_ROOT / dir_name / "Preferences"
    if profile_prefs_path.exists():
        try:
            prefs = read_json(profile_prefs_path)
            # Ensure the profile has proper identification
            prefs.setdefault("profile", {})
            prefs["profile"]["name"] = display_name
            prefs["profile"]["is_using_default_name"] = False
            # Add profile stability markers
            prefs["profile"]["is_ephemeral"] = False
            prefs["profile"]["is_managed"] = False
            # Add additional stability markers
            prefs["profile"]["is_using_default_avatar"] = True
            prefs["profile"]["is_using_default_theme"] = True
            prefs["profile"]["avatar_icon"] = "chrome://theme/IDR_PROFILE_AVATAR_26"
            prefs["profile"]["profile_color_seed"] = -5715974
            prefs["profile"]["profile_highlight_color"] = -14737376
            # CRITICAL: Remove crash status that causes Chrome to delete profiles
            if "exit_type" in prefs["profile"]:
                del prefs["profile"]["exit_type"]
            # Set a clean exit type
            prefs["profile"]["exit_type"] = "Normal"
            write_json_atomic(profile_prefs_path, prefs, do_backup=True)
        except Exception as e:
            log(f"Warning: Could not update profile preferences for {dir_name}: {e}", "!")

    # Create a profile lock file to prevent Chrome from deleting the profile
    lock_file = CHROME_ROOT / dir_name / ".profile_lock"
    try:
        with open(lock_file, 'w') as f:
            f.write(f"Profile locked by arc-exporter at {dt.datetime.now().isoformat()}\n")
            f.write(f"Display name: {display_name}\n")
            f.write("This file prevents Chrome from deleting this profile.\n")
        log(f"Created profile lock file for {dir_name}", "OK")
    except Exception as e:
        log(f"Warning: Could not create lock file for {dir_name}: {e}", "!")

def copy_extensions_to_chrome(arc_profile_dir: Path, chrome_profile_dir: Path):
    """Per-profile, non-corrupting extension install.
    Uses temporary External Extension descriptors only while launching the
    target profile, then removes them to avoid cross-profile installs.
    """
    # Desired extensions from Arc
    desired: set[str] = {e.get("chrome_id") for e in list_arc_extensions(arc_profile_dir)}
    for e in scan_extensions_fs(arc_profile_dir):
        cid = e.get("chrome_id")
        if cid:
            desired.add(cid)
    desired = {cid for cid in desired if isinstance(cid, str)}
    if not desired:
        return

    # Write temporary External Extensions descriptors
    ext_desc_dir = HOME / "Library/Application Support/Google/Chrome/External Extensions"
    ensure(ext_desc_dir)
    # track created files to remove after install
    created: list[Path] = []
    try:
        for ext_id in sorted(desired):
            desc_path = ext_desc_dir / f"{ext_id}.json"
            obj = {"external_update_url": "https://clients2.google.com/service/update2/crx"}
            with desc_path.open("w", encoding="utf-8") as f:
                json.dump(obj, f)
            created.append(desc_path)

        # Launch Chrome focused on this specific profile to let it fetch installs
        chrome_app = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        profile_dir_name = chrome_profile_dir.name
        proc = subprocess.Popen([
            chrome_app,
            f"--profile-directory={profile_dir_name}",
            "--no-first-run",
            "--no-default-browser-check",
            "about:blank",
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Wait up to 120s for installs; stop early if at least one appears
        target_ext_root = chrome_profile_dir / "Extensions"
        start = time.time()
        installed_any = False
        while time.time() - start < 120:
            if target_ext_root.exists():
                dirs = [d for d in target_ext_root.iterdir() if d.is_dir()]
                if any(d.name in desired for d in dirs):
                    installed_any = True
                    break
            time.sleep(2)

        # Terminate Chrome quietly
        try:
            proc.terminate()
            proc.wait(timeout=10)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

        # If nothing installed, leave as-is (user can still sign-in/sync later)
        _ = installed_any
    finally:
        # Remove temporary descriptors to avoid cross-profile installs
        for p in created:
            try:
                p.unlink()
            except Exception:
                pass

# ---------- Password export (CSV for Zen) ----------
def keychain_secret():
    # Try common Chromium variants on macOS
    for svc in ["Arc Safe Storage", "Chrome Safe Storage", "Chromium Safe Storage"]:
        try:
            r = subprocess.run(["security", "find-generic-password", "-w", "-s", svc],
                               capture_output=True, text=True)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.strip()
        except Exception:
            pass
    return None

def keychain_secret_for(service_name: str):
    try:
        r = subprocess.run(["security", "find-generic-password", "-w", "-s", service_name],
                           capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except Exception:
        pass
    return None

def derive_aes_key(secret: str):
    # PBKDF2(HMAC-SHA1, secret, 'saltysalt', 1003, 16) — Chromium macOS v10 scheme
    import hashlib
    return hashlib.pbkdf2_hmac('sha1', secret.encode('utf-8'), b"saltysalt", 1003, dklen=16)

def decrypt_v10_openssl(ciphertext: bytes, aes_key: bytes):
    # AES-128-CBC, iv = 16 spaces, PKCS#7
    import binascii
    iv_hex = binascii.hexlify(b' ' * 16).decode()
    key_hex = binascii.hexlify(aes_key).decode()
    with tempfile.NamedTemporaryFile(delete=False) as tf_in:
        tf_in.write(ciphertext)
        in_path = tf_in.name
    try:
        res = subprocess.run(
            ["openssl", "enc", "-d", "-aes-128-cbc", "-K", key_hex, "-iv", iv_hex, "-in", in_path],
            capture_output=True
        )
        if res.returncode == 0:
            return res.stdout.decode("utf-8", errors="ignore")
        return ""
    finally:
        try: os.unlink(in_path)
        except Exception: pass

def encrypt_v10_openssl(plaintext: str, aes_key: bytes) -> bytes:
    import binascii
    data = plaintext.encode("utf-8") if isinstance(plaintext, str) else plaintext
    iv_hex = binascii.hexlify(b' ' * 16).decode()
    key_hex = binascii.hexlify(aes_key).decode()
    with tempfile.NamedTemporaryFile(delete=False) as tf_in:
        tf_in.write(data)
        in_path = tf_in.name
    try:
        res = subprocess.run(
            ["openssl", "enc", "-aes-128-cbc", "-K", key_hex, "-iv", iv_hex, "-in", in_path],
            capture_output=True
        )
        if res.returncode == 0:
            return b"v10" + res.stdout
        return b""
    finally:
        try: os.unlink(in_path)
        except Exception: pass

def export_passwords_csv(arc_profile_dir: Path, out_csv: Path):
    db = arc_profile_dir / "Login Data"
    if not db.exists():
        log(f"No Login Data in {arc_profile_dir.name}; skipping passwords.", "!")
        return False
    tmp = out_csv.parent / f"{arc_profile_dir.name}-LoginData.sqlite"
    shutil.copy2(db, tmp)
    conn = sqlite3.connect(str(tmp))
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    try:
        cur.execute("SELECT origin_url, username_value, password_value FROM logins")
        rows = cur.fetchall()
    finally:
        conn.close()
        try: tmp.unlink()
        except Exception: pass

    secret = keychain_secret()
    aes_key = derive_aes_key(secret) if secret else None
    ensure(out_csv.parent)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url", "username", "password"])
        for r in rows:
            url = r["origin_url"] or ""
            user = r["username_value"] or ""
            pwd = ""
            pv = r["password_value"]
            if isinstance(pv, (bytes, bytearray)) and len(pv) >= 3:
                if aes_key and pv.startswith(b"v10"):
                    try:
                        pwd = decrypt_v10_openssl(pv[3:], aes_key)
                    except Exception:
                        pwd = ""
                elif not isinstance(pv, str):
                    try:
                        pwd = pv.decode("utf-8", errors="ignore")
                    except Exception:
                        pwd = ""
            w.writerow([url, user, pwd])
    log(f"Passwords CSV → {out_csv}", "OK")
    return True


# ---------- Cookies (experimental) ----------
def chrome_aes_key_from_local_state(local_state_path: Path):
    try:
        d = read_json(local_state_path)
        # On macOS pre-v80, Chrome used Keychain; newer uses DPAPI/V10 on Windows; for Arc we try Keychain secret
        secret = keychain_secret()
        if not secret:
            return None
        return derive_aes_key(secret)
    except Exception:
        return None


def chrome_decrypt_cookie_value(encrypted_value: bytes, aes_key: bytes) -> str:
    if not encrypted_value:
        return ""
    try:
        if encrypted_value.startswith(b"v10") and aes_key:
            return decrypt_v10_openssl(encrypted_value[3:], aes_key) or ""
        # fallback best-effort
        try:
            return encrypted_value.decode("utf-8", errors="ignore")
        except Exception:
            return ""
    except Exception:
        return ""


def export_cookies_sqlite(arc_profile_dir: Path, out_sqlite: Path):
    cookies_db = arc_profile_dir / "Cookies"
    if not cookies_db.exists():
        raise FileNotFoundError("Arc Cookies database not found")
    aes_key = chrome_aes_key_from_local_state(ARC_LOCAL_STATE)

    # Read Chromium cookies
    tmp = out_sqlite.parent / f"{arc_profile_dir.name}-Cookies.sqlite"
    shutil.copy2(cookies_db, tmp)
    conn = sqlite3.connect(str(tmp))
    # Force bytes for all text to avoid sqlite trying to decode encrypted blobs
    conn.text_factory = bytes
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    try:
        cur.execute("SELECT host_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly, samesite, creation_utc, last_access_utc FROM cookies")
        rows = cur.fetchall()
    finally:
        conn.close()
    try:
        tmp.unlink()
    except Exception:
        pass

    # Build Firefox cookies.sqlite
    if out_sqlite.exists():
        out_sqlite.unlink()
    ff = sqlite3.connect(str(out_sqlite))
    c = ff.cursor()
    # schema compatible with Firefox (modern)
    c.executescript(
        """
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS moz_cookies (
            id INTEGER PRIMARY KEY,
            originAttributes TEXT NOT NULL DEFAULT '',
            name TEXT,
            value TEXT,
            host TEXT,
            path TEXT,
            expiry INTEGER,
            lastAccessed INTEGER,
            creationTime INTEGER,
            isSecure INTEGER,
            isHttpOnly INTEGER,
            inBrowserElement INTEGER DEFAULT 0,
            sameSite INTEGER,
            rawSameSite INTEGER DEFAULT 0,
            schemeMap INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS moz_basedomain ON moz_cookies (host);
        """
    )

    def b2s(x):
        if isinstance(x, (bytes, bytearray)):
            return x.decode("utf-8", errors="ignore")
        return x if isinstance(x, str) else ""

    def chromium_ts_to_unix(ts):
        # Chromium stores microseconds since 1601-01-01
        try:
            return int((int(ts) - 11644473600000000) / 1000000)
        except Exception:
            return 0

    for r in rows:
        host = b2s(r["host_key"]) or ""
        name = b2s(r["name"]) or ""
        v = b2s(r["value"]) or ""
        if not v:
            enc = r["encrypted_value"]
            if isinstance(enc, (bytes, bytearray)):
                v = chrome_decrypt_cookie_value(enc, aes_key)
            if not v:
                v = b2s(enc)
        path = b2s(r["path"]) or "/"
        expiry = chromium_ts_to_unix(r["expires_utc"]) or 0
        creation = int(chromium_ts_to_unix(r["creation_utc"]) * 1e6)
        lastacc = int(chromium_ts_to_unix(r["last_access_utc"]) * 1e6)
        is_secure = 1 if (r["is_secure"] if not isinstance(r["is_secure"], (bytes, bytearray)) else int(b2s(r["is_secure"]) or 0)) else 0
        is_httponly = 1 if (r["is_httponly"] if not isinstance(r["is_httponly"], (bytes, bytearray)) else int(b2s(r["is_httponly"]) or 0)) else 0
        samesite = r["samesite"] if isinstance(r["samesite"], int) else 0
        c.execute(
            "INSERT INTO moz_cookies (originAttributes, name, value, host, path, expiry, lastAccessed, creationTime, isSecure, isHttpOnly, sameSite) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("", name, v, host, path, expiry, lastacc, creation, is_secure, is_httponly, samesite)
        )
    ff.commit()
    ff.close()

# ---------- Chrome merge (passwords + cards) ----------
def merge_credentials_into_chrome(arc_profile_dir: Path, chrome_profile_dir: Path):
    # Read Arc logins
    arc_db = arc_profile_dir / "Login Data"
    if not arc_db.exists():
        return
    tmp = chrome_profile_dir / f"tmp-Arc-LoginData-{NOW}.sqlite"
    shutil.copy2(arc_db, tmp)
    conn = sqlite3.connect(str(tmp))
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT origin_url, username_value, password_value FROM logins")
    rows = cur.fetchall()
    conn.close()
    try: tmp.unlink()
    except Exception: pass

    # Prepare Chrome DB
    chrome_db = chrome_profile_dir / "Login Data"
    chrome_secret = keychain_secret_for("Chrome Safe Storage") or keychain_secret_for("Chromium Safe Storage")
    if not chrome_secret:
        raise RuntimeError("Chrome Safe Storage key not available")
    chrome_key = derive_aes_key(chrome_secret)
    arc_secret = keychain_secret()
    arc_key = derive_aes_key(arc_secret) if arc_secret else None

    # Open Chrome DB and introspect schema
    conn = sqlite3.connect(str(chrome_db))
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(logins)")
    cols = [row[1] for row in cur.fetchall()]  # name at index 1
    # Helper: Chrome time in microseconds since 1601-01-01
    import time
    now_unix = int(time.time())
    chrome_time = int((now_unix + 11644473600) * 1_000_000)
    from urllib.parse import urlparse

    for r in rows:
        url = r["origin_url"] or ""
        user = r["username_value"] or ""
        enc = r["password_value"]
        plaintext = ""
        if isinstance(enc, (bytes, bytearray)) and len(enc) >= 3 and arc_key and enc.startswith(b"v10"):
            try:
                plaintext = decrypt_v10_openssl(enc[3:], arc_key)
            except Exception:
                plaintext = ""
        elif isinstance(enc, (bytes, bytearray)):
            try:
                plaintext = enc.decode("utf-8", errors="ignore")
            except Exception:
                plaintext = ""
        new_blob = encrypt_v10_openssl(plaintext, chrome_key) if plaintext else b""
        realm = url
        try:
            u = urlparse(url)
            if u.scheme and u.netloc:
                realm = f"{u.scheme}://{u.netloc}"
        except Exception:
            pass

        # Build row dict with defaults; only include columns present
        row = {
            "origin_url": url,
            "action_url": "",
            "username_element": "",
            "username_value": user,
            "password_element": "",
            "password_value": new_blob,
            "submit_element": "",
            "signon_realm": realm,
            "date_created": chrome_time,
            "date_last_used": chrome_time,
            "date_password_modified": chrome_time,
            "blacklisted_by_user": 0,
            "scheme": 0,
            "password_type": 0,
            "times_used": 0,
            "display_name": "",
            "icon_url": "",
            "federation_origin": "",
            "skip_zero_click": 0,
        }
        # Remove existing duplicate (unique key subset)
        try:
            cur.execute("DELETE FROM logins WHERE origin_url=? AND username_value=? AND signon_realm=?", (url, user, realm))
        except Exception:
            pass
        insert_cols = [c for c in row.keys() if c in cols]
        placeholders = ", ".join(["?"] * len(insert_cols))
        sql = f"INSERT INTO logins ({', '.join(insert_cols)}) VALUES ({placeholders})"
        cur.execute(sql, [row[c] for c in insert_cols])
    conn.commit()
    conn.close()


def merge_cards_into_chrome(arc_profile_dir: Path, chrome_profile_dir: Path):
    webdata = arc_profile_dir / "Web Data"
    if not webdata.exists():
        return
    tmp = chrome_profile_dir / f"tmp-Arc-WebData-{NOW}.sqlite"
    shutil.copy2(webdata, tmp)
    conn = sqlite3.connect(str(tmp))
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    rows = []
    try:
        cur.execute("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards")
        rows = cur.fetchall()
    except sqlite3.OperationalError:
        try:
            cur.execute("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM masked_credit_cards")
            rows = cur.fetchall()
        except sqlite3.OperationalError:
            rows = []
    conn.close()
    try: tmp.unlink()
    except Exception: pass

    chrome_webdata = chrome_profile_dir / "Web Data"
    chrome_secret = keychain_secret_for("Chrome Safe Storage") or keychain_secret_for("Chromium Safe Storage")
    if not chrome_secret:
        raise RuntimeError("Chrome Safe Storage key not available")
    chrome_key = derive_aes_key(chrome_secret)
    arc_secret = keychain_secret()
    arc_key = derive_aes_key(arc_secret) if arc_secret else None

    conn = sqlite3.connect(str(chrome_webdata))
    cur = conn.cursor()
    # Ensure table exists
    try:
        cur.execute("CREATE TABLE IF NOT EXISTS credit_cards (name_on_card TEXT, expiration_month INTEGER, expiration_year INTEGER, card_number_encrypted BLOB)")
    except Exception:
        pass
    for r in rows:
        name = r["name_on_card"] or ""
        em = r["expiration_month"] or 0
        ey = r["expiration_year"] or 0
        enc = r["card_number_encrypted"]
        plaintext = ""
        if isinstance(enc, (bytes, bytearray)) and len(enc) >= 3 and arc_key and enc.startswith(b"v10"):
            try:
                plaintext = decrypt_v10_openssl(enc[3:], arc_key)
            except Exception:
                plaintext = ""
        # Re-encrypt PAN for Chrome
        new_blob = encrypt_v10_openssl(plaintext, chrome_key) if plaintext else b""
        cur.execute("INSERT INTO credit_cards (name_on_card, expiration_month, expiration_year, card_number_encrypted) VALUES (?, ?, ?, ?)", (name, em, ey, new_blob))
    conn.commit()
    conn.close()
# ---------- Cards (reference only) ----------
def export_cards_reference(arc_profile_dir: Path, out_csv: Path):
    webdata = arc_profile_dir / "Web Data"
    if not webdata.exists():
        log(f"No Web Data in {arc_profile_dir.name}; skipping cards.", "!")
        return False
    tmp = out_csv.parent / f"{arc_profile_dir.name}-WebData.sqlite"
    shutil.copy2(webdata, tmp)
    conn = sqlite3.connect(str(tmp))
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    rows = []
    try:
        # Prefer full card table if present (with encrypted PAN)
        try:
            cur.execute("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards")
            rows = cur.fetchall()
        except sqlite3.OperationalError:
            # Fallback to masked cards; some schemas use masked_credit_cards
            try:
                cur.execute("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted, last_four FROM masked_credit_cards")
                rows = cur.fetchall()
            except sqlite3.OperationalError:
                # Old schema without encrypted column
                try:
                    cur.execute("SELECT name_on_card, expiration_month, expiration_year, last_four FROM masked_credit_cards")
                    rows = cur.fetchall()
                except sqlite3.OperationalError:
                    rows = []
    except sqlite3.OperationalError:
        pass
    finally:
        conn.close()
        try: tmp.unlink()
        except Exception: pass

    ensure(out_csv.parent)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["name_on_card", "expiration_month", "expiration_year", "last4"])
        # Attempt to decrypt last4 from encrypted PAN
        secret = keychain_secret()
        aes_key = derive_aes_key(secret) if secret else None
        for r in rows:
            last4 = ""
            keys = r.keys() if isinstance(r, sqlite3.Row) else []
            enc = r["card_number_encrypted"] if isinstance(r, sqlite3.Row) and "card_number_encrypted" in keys else None
            if enc and isinstance(enc, (bytes, bytearray)):
                if aes_key and enc.startswith(b"v10"):
                    try:
                        pan = decrypt_v10_openssl(enc[3:], aes_key)
                        if isinstance(pan, str) and len(pan) >= 4:
                            last4 = pan[-4:]
                    except Exception:
                        last4 = ""
            if not last4:
                lf = (r["last_four"] if isinstance(r, sqlite3.Row) and "last_four" in keys else "") or ""
                last4 = str(lf)[-4:] if lf else ""
            w.writerow([r["name_on_card"] or "", r["expiration_month"] or "", r["expiration_year"] or "", last4])
    log(f"Cards (reference) CSV → {out_csv} (PAN/CVV not exported)", "OK")
    return True

# ---------- Extensions (Arc → AMO → Zen policies) ----------
def http_get_json(url, params=None, timeout=20):
    if params:
        url = url + ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": "arc-to-zen/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))

def list_arc_extensions(profile_dir: Path):
    prefs = read_json(profile_dir / "Preferences")
    results = []
    exts = (prefs.get("extensions", {}) or {}).get("settings", {}) if prefs else {}
    for ext_id, meta in exts.items():
        state = meta.get("state")
        manifest = meta.get("manifest") or {}
        name = manifest.get("name") or meta.get("path")
        if not name: continue
        # ignore themes
        if manifest.get("theme"):
            continue
        if state not in (1, True):
            continue
        results.append({
            "chrome_id": ext_id,
            "name": name,
            "version": manifest.get("version"),
            "homepage_url": manifest.get("homepage_url"),
        })
    return results


def scan_extensions_fs(profile_dir: Path):
    ext_root = profile_dir / "Extensions"
    results = []
    if not ext_root.exists():
        return results
    try:
        for chrome_id_dir in sorted(ext_root.iterdir()):
            if not chrome_id_dir.is_dir():
                continue
            chrome_id = chrome_id_dir.name
            # pick latest version folder
            version_dirs = [d for d in chrome_id_dir.iterdir() if d.is_dir()]
            if not version_dirs:
                continue
            latest = sorted(version_dirs, key=lambda p: p.name, reverse=True)[0]
            manifest_path = latest / "manifest.json"
            manifest = {}
            try:
                with manifest_path.open("r", encoding="utf-8") as f:
                    manifest = json.load(f)
            except Exception:
                manifest = {}
            if manifest.get("theme"):
                continue
            # Resolve localized names from manifest and _locales
            def resolve_i18n_name(raw_name: str) -> str:
                if not isinstance(raw_name, str):
                    return chrome_id
                if not (raw_name.startswith("__MSG_") and raw_name.endswith("__")):
                    return raw_name
                key = raw_name[6:-2]
                default_locale = manifest.get("default_locale")
                locales_dir = latest / "_locales"
                if not locales_dir.is_dir():
                    return chrome_id
                candidate_locale_files = []
                # prefer manifest default
                if default_locale and (locales_dir / default_locale / "messages.json").exists():
                    candidate_locale_files.append(locales_dir / default_locale / "messages.json")
                # common fallbacks
                for loc in ("en-US", "en"):
                    p = locales_dir / loc / "messages.json"
                    if p.exists() and p not in candidate_locale_files:
                        candidate_locale_files.append(p)
                # any other locales
                for p in sorted(locales_dir.glob("*/messages.json")):
                    if p not in candidate_locale_files:
                        candidate_locale_files.append(p)
                for p in candidate_locale_files:
                    try:
                        data = json.load(open(p, "r", encoding="utf-8"))
                        msg = data.get(key) or {}
                        if isinstance(msg, dict) and msg.get("message"):
                            return msg.get("message")
                    except Exception:
                        continue
                return chrome_id

            raw_name = manifest.get("name") or chrome_id
            name = resolve_i18n_name(raw_name)
            version = manifest.get("version") or latest.name
            homepage = manifest.get("homepage_url")
            results.append({
                "chrome_id": chrome_id,
                "name": name,
                "version": version,
                "homepage_url": homepage,
            })
    except Exception:
        pass
    return results

def collect_unique_arc_extensions():
    # DEPRECATED: This function combined extensions from all profiles
    # Now each profile should handle its own extensions individually
    # Keeping for backward compatibility but should not be used
    all_exts = []
    for prof in arc_profiles():
        all_exts.extend(list_arc_extensions(prof))
    dedup = {}
    for e in all_exts:
        dedup.setdefault(e["chrome_id"], e)
    return list(dedup.values())

def fetch_browser_mappings():
    # Paginated endpoint
    out = {}
    url = AMO_BROWSER_MAPPINGS
    while url:
        data = http_get_json(url)
        for row in data.get("results", []):
            chrome_id = row.get("chrome_id") or row.get("extension_id") or row.get("external_id")
            guid = row.get("amo_guid") or row.get("guid")
            slug = row.get("amo_slug") or row.get("slug")
            if chrome_id and (guid or slug):
                out[chrome_id] = {"guid": guid, "slug": slug}
        url = data.get("next")
    return out

def amo_search_candidates(name, limit=6):
    params = {"q": name, "app": "firefox", "type": "extension", "page_size": limit, "sort": "relevance"}
    return http_get_json(AMO_SEARCH, params=params)


def best_amo_match(name: str, candidates: list[dict]) -> dict | None:
    # prefer exact slug/name matches first, then fuzzy on en-US
    if not isinstance(name, str) or not candidates:
        return None
    # exact name match in any locale
    for c in candidates:
        nm = c.get("name")
        if isinstance(nm, dict) and any(v == name for v in nm.values() if isinstance(v, str)):
            return c
        if isinstance(nm, str) and nm == name:
            return c
    # fuzzy on en-US
    scored = []
    for c in candidates:
        nm = c.get("name")
        if isinstance(nm, dict):
            nm = nm.get("en-US") or next((v for v in nm.values() if isinstance(v, str)), "")
        if isinstance(nm, str):
            ratio = difflib.SequenceMatcher(None, name.lower(), nm.lower()).ratio()
            scored.append((ratio, c))
    scored.sort(reverse=True, key=lambda x: x[0])
    return scored[0][1] if scored and scored[0][0] >= 0.6 else None


# ---------- CLI Orchestration ----------
def find_zen_distribution_dir() -> Path | None:
    for c in ZEN_CANDIDATES:
        app = Path(c)
        dist = app / "Contents/Resources/distribution"
        if dist.exists():
            return dist
    return None


def build_policies_json(matched: list[dict]) -> dict:
    extension_settings = {}
    for m in matched:
        slug = m.get("slug")
        guid = m.get("guid")
        if not slug or not guid:
            continue
        extension_settings[guid] = {
            "installation_mode": "force_installed",
            "install_url": AMO_LATEST_XPI.format(slug=slug),
        }
    return {
        "policies": {
            "ExtensionSettings": extension_settings
        }
    }


def write_text(path: Path, content: str):
    ensure(path.parent)
    with path.open("w", encoding="utf-8") as f:
        f.write(content)


def export_extensions_html(arc_profile_dir: Path, out_html: Path, profile_name: str = "Arc Profile"):
    """Export extensions to HTML format with Chrome Web Store links"""
    # Combine preferences-based and filesystem-based detections (reusing do_extensions_mapping logic)
    exts_pref = list_arc_extensions(arc_profile_dir)
    exts_fs = scan_extensions_fs(arc_profile_dir)

    # Deduplicate by chrome_id, prefer filesystem metadata (better i18n names)
    dedup = {e.get("chrome_id"): e for e in exts_pref}
    dedup.update({e.get("chrome_id"): e for e in exts_fs})
    exts = [v for k, v in dedup.items() if k]

    if not exts:
        log(f"No extensions found in {profile_name}; skipping extensions HTML.", "!")
        return False

    # Generate HTML content
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Extensions from {profile_name}</title>
    <meta charset="utf-8">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        .extension {{ margin: 10px 0; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }}
        .extension-name {{ font-weight: bold; font-size: 16px; }}
        .extension-id {{ color: #666; font-size: 12px; font-family: monospace; }}
        .extension-version {{ color: #888; font-size: 14px; }}
        .chrome-link {{ color: #1a73e8; text-decoration: none; }}
        .chrome-link:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <h1>Extensions from {profile_name}</h1>
    <p>Total extensions: {len(exts)}</p>
"""

    for ext in sorted(exts, key=lambda x: x.get("name", "").lower()):
        name = ext.get("name", "Unknown Extension")
        chrome_id = ext.get("chrome_id", "")
        version = ext.get("version", "")
        homepage = ext.get("homepage_url", "")

        # Chrome Web Store URL
        chrome_store_url = f"https://chrome.google.com/webstore/detail/{chrome_id}"

        html_content += f"""    <div class="extension">
        <div class="extension-name">
            <a href="{chrome_store_url}" class="chrome-link" target="_blank">{name}</a>
        </div>
        <div class="extension-id">ID: {chrome_id}</div>"""

        if version:
            html_content += f"""
        <div class="extension-version">Version: {version}</div>"""

        if homepage:
            html_content += f"""
        <div>Homepage: <a href="{homepage}" target="_blank">{homepage}</a></div>"""

        html_content += """
    </div>
"""

    html_content += """</body>
</html>"""

    # Write HTML file
    ensure(out_html.parent)
    write_text(out_html, html_content)
    log(f"Extensions HTML → {out_html}", "OK")
    return True


# DEPRECATED: run_bookmarks_export_per_profile function removed
# Use export_pinned_bookmarks from az.bookmarks instead


def orchestrate(copy_profiles: bool, do_passwords: bool, do_cards: bool, do_bookmarks: bool, do_extensions_mapping: bool, do_cookies: bool, do_extensions_html: bool = False, experimental_extensions: bool = False):
    # Start monitoring Chrome profiles (silent unless VERBOSE)
    if VERBOSE:
        chrome_monitor.start_monitoring()

    try:
        ensure(OUT_ROOT)
        ensure(PROFILES_DIR)
        # No combined dir; all outputs are per-profile now

        # Clean previous outputs to avoid duplicates
        if OUT_ROOT.exists():
            try:
                shutil.rmtree(OUT_ROOT)
            except Exception:
                pass
        ensure(OUT_ROOT)
        log(f"Output folder: {OUT_ROOT}")

        profiles = arc_profiles()
        display_names = arc_display_names()

        # 1) Optionally copy Arc profiles into unique Chrome profiles and register them
        if copy_profiles:
            ensure(CHROME_ROOT)
            log(f"Found {len(profiles)} Arc profiles to copy", "OK")
            total = len(profiles)
            for i, src in enumerate(profiles, 1):
                print_progress(i - 1, total, f" preparing {src.name}")
                display_name = display_names.get(src.name, src.name)
                log(f"Processing Arc profile {i}/{len(profiles)}: {src.name} (display: {display_name})", "OK")

                # Check what data files exist in this Arc profile
                data_files = []
                for data_file in ["History", "Web Data", "Login Data", "Cookies", "Preferences"]:
                    if (src / data_file).exists():
                        data_files.append(data_file)
                log(f"Arc profile {src.name} contains: {', '.join(data_files) if data_files else 'no data files'}", "OK")

                dir_name = next_free_chrome_profile()
                dst = CHROME_ROOT / dir_name
                copied = copy_profile_safely(src, dst)
                register_chrome_profile(dir_name, display_name)
                log(f"Registered Chrome profile: {copied.name} for Arc profile: {src.name}", "OK")
                # Merge credentials and cards into Chrome profile
                try:
                    merge_credentials_into_chrome(src, copied)
                except Exception:
                    pass
                try:
                    merge_cards_into_chrome(src, copied)
                except Exception:
                    pass
                if experimental_extensions:
                    try:
                        copy_extensions_to_chrome(src, copied)
                    except Exception:
                        pass
                print_progress(i, total, f" migrated {display_name}")

            sys.stdout.write("\n")
        else:
            log("Profile copy skipped (disable default with --no-copy-profiles)", "-")

        # 2) Passwords CSV per profile
        if do_passwords:
            for src in profiles:
                # Use Arc display name when available
                disp = display_names.get(src.name, src.name)
                prof_dir = PROFILES_DIR / safe_dir_name(disp)
                ensure(prof_dir)
                out_csv = prof_dir / f"passwords_{NOW}.csv"
                export_passwords_csv(src, out_csv)
        else:
            log("Passwords export skipped (disable skip by default)", "-")

        # 3) Cards (reference) per profile
        if do_cards:
            for src in profiles:
                disp = display_names.get(src.name, src.name)
                prof_dir = PROFILES_DIR / safe_dir_name(disp)
                ensure(prof_dir)
                out_csv = prof_dir / f"cards_{NOW}.csv"
                export_cards_reference(src, out_csv)
        else:
            log("Cards export skipped", "-")

        # 4) Bookmarks HTML per profile
        if do_bookmarks:
            for src in profiles:
                disp = display_names.get(src.name, src.name)
                prof_dir = PROFILES_DIR / safe_dir_name(disp)
                ensure(prof_dir)
                out_html = prof_dir / f"bookmarks_{NOW}.html"
                log(f"Exporting bookmarks for Arc profile: {src.name} (display: {disp})", "OK")
                export_pinned_bookmarks(out_html, space_title=disp)
                log(f"Bookmarks HTML → {out_html}", "OK")
        else:
            log("Bookmarks export skipped", "-")

        # 5) Extensions HTML export per profile
        if do_extensions_html:
            for src in profiles:
                disp = display_names.get(src.name, src.name)
                prof_dir = PROFILES_DIR / safe_dir_name(disp)
                ensure(prof_dir)
                out_html = prof_dir / f"extensions_{NOW}.html"
                export_extensions_html(src, out_html, disp)
        else:
            log("Extensions HTML export skipped", "-")

        # 6) Extension mapping and per-profile policies (experimental; disabled by default)
        if do_extensions_mapping:
            mappings = fetch_browser_mappings()
            for prof in profiles:
                disp = display_names.get(prof.name, prof.name)
                prof_dir = PROFILES_DIR / safe_dir_name(disp)
                ensure(prof_dir)
                # Combine preferences-based and filesystem-based detections
                exts_pref = list_arc_extensions(prof)
                exts_fs = scan_extensions_fs(prof)
                # Deduplicate by chrome_id, prefer filesystem metadata (better i18n names)
                dedup = {e.get("chrome_id"): e for e in exts_pref}
                dedup.update({e.get("chrome_id"): e for e in exts_fs})
                exts = [v for k, v in dedup.items() if k]
                report_rows = []
                matched = []
                for e in exts:
                    chrome_id = e.get("chrome_id")
                    name = e.get("name")
                    m = mappings.get(chrome_id)
                    entry = {"chrome_id": chrome_id, "name": name}
                    if m:
                        entry.update({"guid": m.get("guid"), "slug": m.get("slug"), "match": "mapping"})
                        matched.append({"guid": m.get("guid"), "slug": m.get("slug"), "name": name})
                    else:
                        # Strict: if no official mapping, skip (do not suggest unrelated addons)
                        entry.update({"candidates": [], "match": "none"})
                    report_rows.append(entry)

                # Write per-profile report
                rep_path = prof_dir / f"extensions_report_{NOW}.json"
                with rep_path.open("w", encoding="utf-8") as f:
                    json.dump({"generated_at": NOW, "extensions": report_rows}, f, indent=2)
                log(f"Extensions report → {rep_path}", "OK")

                # Per-profile policies
                policies = build_policies_json([r for r in matched if r.get("slug") and r.get("guid")])
                pol_path = prof_dir / f"policies_{NOW}.json"
                with pol_path.open("w", encoding="utf-8") as f:
                    json.dump(policies, f, indent=2)
                log(f"Suggested policies.json → {pol_path}", "OK")
        else:
            log("Extensions mapping skipped", "-")

        # 6) Cookies per profile (experimental)
        if do_cookies:
            for src in profiles:
                disp = display_names.get(src.name, src.name)
                prof_dir = PROFILES_DIR / safe_dir_name(disp)
                ensure(prof_dir)
                out_sqlite = prof_dir / f"cookies_{NOW}.sqlite"
                try:
                    export_cookies_sqlite(src, out_sqlite)
                    log(f"Cookies (experimental) → {out_sqlite}", "OK")
                except Exception as e:
                    log(f"Cookies export failed for {disp}: {e}", "!")
        else:
            log("Cookies export skipped", "-")

        log("All done.", "OK")

    except Exception as e:
        log(f"Error during orchestration: {e}", "!")
        raise
    finally:
        # Stop monitoring
        if VERBOSE:
            chrome_monitor.stop_monitoring()


def parse_args(argv: list[str] | None = None):
    p = argparse.ArgumentParser(description="Arc → Zen helper: exports data and suggests extensions policies.")
    p.add_argument("--no-copy-profiles", action="store_true", help="Do not copy Arc profiles to new Chrome profiles")
    p.add_argument("--no-passwords", action="store_true", help="Skip passwords CSV export")
    p.add_argument("--no-cards", action="store_true", help="Skip cards reference export")
    p.add_argument("--no-bookmarks", action="store_true", help="Skip bookmarks HTML export")
    p.add_argument("--no-extensions-html", action="store_true", help="Skip extensions HTML export")
    p.add_argument("--experimental-amo-mapping", action="store_true", help="EXPERIMENTAL: try to map extensions to AMO and write policies.json")
    p.add_argument("--import-cookies", action="store_true", help="Experimental: export Arc cookies to Firefox cookies.sqlite per profile")
    p.add_argument("--experimental-extensions", action="store_true", help="EXPERIMENTAL: attempt to preinstall Chrome extensions per profile (unstable)")
    return p.parse_args(argv)


def main():
    args = parse_args()
    orchestrate(
        copy_profiles=not bool(args.no_copy_profiles),
        do_passwords=not bool(args.no_passwords),
        do_cards=not bool(args.no_cards),
        do_bookmarks=not bool(args.no_bookmarks),
        do_extensions_html=not bool(args.no_extensions_html),
        do_extensions_mapping=bool(args.experimental_amo_mapping),
        do_cookies=bool(args.import_cookies),
        experimental_extensions=bool(args.experimental_extensions),
    )


if __name__ == "__main__":
    main()
