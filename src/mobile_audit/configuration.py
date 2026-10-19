"""Trusted configuration outside the audited repository, with portable paths."""
import copy
import os
from pathlib import Path

import yaml


def _merge(base: dict, override: dict) -> dict:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge(base[key], value)
        else:
            base[key] = copy.deepcopy(value)
    return base


def _read(path: Path) -> dict:
    data = yaml.safe_load(path.read_text()) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Configuration must be a mapping: {path}")
    for role in ("primary", "reviewer"):
        settings = data.get(role)
        if not isinstance(settings, dict) or not settings.get("path"):
            continue
        model = Path(os.path.expandvars(str(settings["path"]))).expanduser()
        if not model.is_absolute():
            model = path.parent / model
        settings["path"] = str(model.resolve())
    return data


def load_config(explicit: Path | None = None, *, user_path: Path | None = None) -> dict:
    """Defaults < private user configuration < explicitly selected configuration.

    Never auto-load configuration from the audit target or current working directory.
    Relative model paths resolve against their configuration file, not the target.
    """
    config = _read(Path(__file__).with_name("default.yaml"))
    private = user_path or Path.home() / ".config" / "mobile-audit" / "config.yaml"
    if private.is_file():
        _merge(config, _read(private.resolve()))
    if explicit is not None:
        _merge(config, _read(explicit.expanduser().resolve()))
    return config
