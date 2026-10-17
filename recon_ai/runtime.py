import os
import shutil
from pathlib import Path

TOOL_DIRS = ("subfinder", "dnsx", "httpx", "katana", "nuclei", "amass")


def prepare_state(state_home, config_dir):
    """Copia chaves para um home gravável. Não cria symlink para /config."""
    home = Path(state_home)
    config_root = home / ".config"
    config_root.mkdir(parents=True, exist_ok=True)
    source_root = Path(config_dir)
    for name in TOOL_DIRS:
        dest = config_root / name
        dest.mkdir(parents=True, exist_ok=True)
        src = source_root / name
        if src.is_dir():
            for item in src.iterdir():
                if item.is_file():
                    shutil.copy2(item, dest / item.name)
        marker = dest / "config.yaml"
        if not marker.exists():
            marker.write_text("{}\n", encoding="utf-8")
    gau = source_root / "gau.toml"
    if gau.is_file():
        shutil.copy2(gau, home / ".gau.toml")
    os.environ["HOME"] = str(home)
    os.environ["XDG_CONFIG_HOME"] = str(config_root)
