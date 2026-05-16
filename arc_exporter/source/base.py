"""Shared abstractions for Arc source readers."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class ArcProfile:
    """A single Arc Browser profile on disk."""

    directory_name: str
    display_name: str
    path: Path

    @property
    def login_data(self) -> Path:
        return self.path / "Login Data"

    @property
    def web_data(self) -> Path:
        return self.path / "Web Data"

    @property
    def cookies(self) -> Path:
        return self.path / "Cookies"

    @property
    def history(self) -> Path:
        return self.path / "History"

    @property
    def preferences(self) -> Path:
        return self.path / "Preferences"

    @property
    def extensions_root(self) -> Path:
        return self.path / "Extensions"

    @property
    def favicons(self) -> Path:
        return self.path / "Favicons"

    def exists(self) -> bool:
        return self.preferences.exists()


@dataclass
class ArcSourceConfig:
    user_data_dir: Path
    local_state_path: Path
    sidebar_path: Path
    safe_storage_services: tuple[str, ...] = field(default_factory=tuple)


class ArcSource(ABC):
    """Per-OS adapter that knows where Arc lives and how to enumerate its profiles."""

    @property
    @abstractmethod
    def config(self) -> ArcSourceConfig: ...

    @abstractmethod
    def is_installed(self) -> bool: ...

    @abstractmethod
    def profiles(self) -> list[ArcProfile]:
        """Return non-system Arc profiles, deterministically ordered."""

    def display_names(self) -> Mapping[str, str]:
        """Return ``{profile_dir_name: display_name}`` from Arc's ``Local State``."""
        local_state = self.config.local_state_path
        if not local_state.exists():
            return {}
        try:
            with local_state.open("r", encoding="utf-8") as f:
                state = json.load(f)
        except (OSError, json.JSONDecodeError):
            return {}
        info = ((state.get("profile") or {}).get("info_cache") or {}) if isinstance(state, dict) else {}
        out: dict[str, str] = {}
        for k, meta in info.items():
            if isinstance(meta, dict):
                out[k] = (meta.get("name") or k) if isinstance(meta.get("name"), str) else k
            else:
                out[k] = k
        return out

    def system_profile_dirs(self) -> set[str]:
        """Identify Arc's hidden ``__ARC_SYSTEM_PROFILE`` containers from ``Local State``."""
        local_state = self.config.local_state_path
        if not local_state.exists():
            return set()
        try:
            state = json.loads(local_state.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return set()
        out: set[str] = set()
        info = ((state.get("profile") or {}).get("info_cache") or {}) if isinstance(state, dict) else {}
        for key, meta in info.items():
            if key == "__ARC_SYSTEM_PROFILE":
                out.add(key)
            if isinstance(meta, dict) and meta.get("name") == "__ARC_SYSTEM_PROFILE":
                out.add(key)
        return out

    def safe_storage_services(self) -> tuple[str, ...]:
        return self.config.safe_storage_services

    def __iter__(self) -> Iterable[ArcProfile]:
        return iter(self.profiles())
