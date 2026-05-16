"""Target browser protocol shared by every adapter.

A :class:`Target` is responsible for:

1. Locating its own user-data directory and Safe-Storage keychain service on the
   current OS.
2. Creating a new profile (or selecting an existing one) for the migration.
3. Importing each artefact kind it supports.

It does **not** quit the browser, decrypt Arc data, or write files outside its own
data tree. Those steps are the orchestrator's responsibility.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from arc_exporter.source.base import ArcProfile

ArtefactKind = Literal[
    "bookmarks",
    "passwords",
    "cards",
    "cookies",
    "history",
    "tabs",
    "extensions",
    "easels",
    "reading_list",
]


@dataclass(frozen=True)
class TargetProfile:
    directory_name: str
    display_name: str
    path: Path


@dataclass
class MigrationRequest:
    artefact_paths: dict[ArtefactKind, Path]
    source_profile: ArcProfile | None = None
    arc_sidebar_path: Path | None = None
    arc_aes_key: bytes | None = None
    target_aes_key: bytes | None = None
    keep_cache_dirs: bool = False
    strip_storage: bool = False
    dry_run: bool = False


@dataclass
class MigrationReport:
    target: str
    profile: str
    succeeded: dict[ArtefactKind, int] = field(default_factory=dict)
    skipped: dict[ArtefactKind, str] = field(default_factory=dict)
    errors: dict[ArtefactKind, str] = field(default_factory=dict)

    def merge(self, other: MigrationReport) -> None:
        for k, v in other.succeeded.items():
            self.succeeded[k] = self.succeeded.get(k, 0) + v
        self.skipped.update(other.skipped)
        self.errors.update(other.errors)


class Target(ABC):
    """Abstract base class for every browser target."""

    name: str = ""
    family: Literal["chromium", "firefox", "safari", "orion"] = "chromium"
    supports: tuple[ArtefactKind, ...] = ()

    @property
    @abstractmethod
    def user_data_dir(self) -> Path: ...

    def keychain_services(self) -> tuple[str, ...]:
        return ()

    @abstractmethod
    def is_installed(self) -> bool: ...

    @abstractmethod
    def process_name(self) -> str: ...

    @abstractmethod
    def create_profile(self, display_name: str, *, dry_run: bool = False) -> TargetProfile: ...

    @abstractmethod
    def migrate_profile(
        self,
        target_profile: TargetProfile,
        request: MigrationRequest,
    ) -> MigrationReport: ...
