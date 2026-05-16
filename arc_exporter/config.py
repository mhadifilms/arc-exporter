"""TOML-loaded config with sensible defaults."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from platformdirs import user_config_dir

from arc_exporter.errors import ConfigError

if sys.version_info >= (3, 11):
    import tomllib  # type: ignore[import-not-found]
else:
    import tomli as tomllib  # type: ignore[import-not-found,no-redef]


@dataclass
class Config:
    output_dir: Path = field(default_factory=lambda: Path.cwd() / "arc-export")
    excluded_profiles: tuple[str, ...] = ()
    keep_cache_dirs: bool = False
    strip_storage: bool = False
    target: str | None = None
    arc_root_override: Path | None = None
    amo_cache_dir: Path | None = None

    @classmethod
    def default_path(cls) -> Path:
        return Path(user_config_dir("arc-exporter")) / "config.toml"

    @classmethod
    def load(cls, path: Path | None = None) -> Config:
        path = path or cls.default_path()
        if not path.exists():
            return cls()
        try:
            with path.open("rb") as f:
                raw = tomllib.load(f)
        except (OSError, tomllib.TOMLDecodeError) as e:
            raise ConfigError(f"could not read {path}: {e}") from e
        return cls._from_dict(raw)

    @classmethod
    def _from_dict(cls, raw: dict[str, Any]) -> Config:
        kwargs: dict[str, Any] = {}
        if "output_dir" in raw:
            kwargs["output_dir"] = Path(raw["output_dir"]).expanduser()
        if "excluded_profiles" in raw:
            kwargs["excluded_profiles"] = tuple(raw["excluded_profiles"])
        if "keep_cache_dirs" in raw:
            kwargs["keep_cache_dirs"] = bool(raw["keep_cache_dirs"])
        if "strip_storage" in raw:
            kwargs["strip_storage"] = bool(raw["strip_storage"])
        if "target" in raw:
            kwargs["target"] = str(raw["target"])
        if "arc_root_override" in raw:
            kwargs["arc_root_override"] = Path(raw["arc_root_override"]).expanduser()
        if "amo_cache_dir" in raw:
            kwargs["amo_cache_dir"] = Path(raw["amo_cache_dir"]).expanduser()
        return cls(**kwargs)
