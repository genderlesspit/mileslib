from pathlib import Path
from mileslib import sm

# Root of the project
PROJECT_ROOT = Path(__file__).resolve().parent

# Standardized project subdirectories
CONFIG_DIR = PROJECT_ROOT / "config"
SRC_DIR = PROJECT_ROOT / "src"
LOG_DIR = PROJECT_ROOT / "logs"
TMP_DIR = PROJECT_ROOT / ".tmp"

# Load config from config/
settings = sm.Config.build(pdir=PROJECT_ROOT)

# Optionally enforce config requirements
REQUIRED_KEYS = ["SECRET_KEY", "POSTGRES_DB", "DJANGO_CLIENT_ID"]
sm.Config.require(REQUIRED_KEYS, pdir=PROJECT_ROOT)

# Expose useful CLI context
def get_context():
    return {
        "root": PROJECT_ROOT,
        "config": settings,
        "log_dir": LOG_DIR,
    }

