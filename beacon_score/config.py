"""
Configuration loader for beacon-score.
Supports YAML and TOML weight config files.
Falls back to DEFAULT_WEIGHTS if no config provided.
"""

import os
from .engine import DEFAULT_WEIGHTS


def load_weights(config_path: str = None) -> dict:
    """
    Load signal weights from a YAML or TOML config file.
    Returns DEFAULT_WEIGHTS if no path given or file not found.
    """
    if not config_path:
        return dict(DEFAULT_WEIGHTS)

    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")

    ext = os.path.splitext(config_path)[1].lower()

    if ext in (".yaml", ".yml"):
        try:
            import yaml
            with open(config_path) as f:
                data = yaml.safe_load(f)
        except ImportError:
            raise ImportError("PyYAML required for YAML config: pip install pyyaml")

    elif ext == ".toml":
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib
            except ImportError:
                raise ImportError("tomllib/tomli required for TOML config: pip install tomli")
        with open(config_path, "rb") as f:
            data = tomllib.load(f)
    else:
        raise ValueError(f"Unsupported config format: {ext}. Use .yaml or .toml")

    weights_data = data.get("weights", data)
    weights = dict(DEFAULT_WEIGHTS)
    for key in DEFAULT_WEIGHTS:
        if key in weights_data:
            val = float(weights_data[key])
            if not (0.0 <= val <= 1.0):
                raise ValueError(f"Weight for '{key}' must be between 0.0 and 1.0, got {val}")
            weights[key] = val

    return weights


def generate_default_config(output_path: str, fmt: str = "yaml"):
    """Write a default config file the user can customize."""
    from .engine import DEFAULT_WEIGHTS, ATTACK_MAP

    if fmt == "toml":
        lines = ["[weights]\n"]
        for k, v in DEFAULT_WEIGHTS.items():
            attack = ATTACK_MAP.get(k, {})
            tid = attack.get("id", "")
            tname = attack.get("name", "")
            lines.append(f"# {tid} - {tname}\n")
            lines.append(f'{k} = {v}\n\n')
        content = "".join(lines)
        with open(output_path, "w") as f:
            f.write(content)
    else:
        lines = ["weights:\n"]
        for k, v in DEFAULT_WEIGHTS.items():
            attack = ATTACK_MAP.get(k, {})
            tid = attack.get("id", "")
            tname = attack.get("name", "")
            lines.append(f"  # {tid} - {tname}\n")
            lines.append(f"  {k}: {v}\n\n")
        content = "".join(lines)
        with open(output_path, "w") as f:
            f.write(content)
