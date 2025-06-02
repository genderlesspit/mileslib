from pathlib import Path
import sys
import pytest
from datetime import datetime
from tests.mileslib_core import StaticMethods as sm

class MilesLogger:
    _configured = False
    _current_log_path = None
    _logger = None

    @staticmethod
    def try_import_loguru():
        loguru = sm.try_import("loguru")
        return loguru.logger

    @staticmethod
    def get_loguru():
        if not MilesLogger._configured:
            raise RuntimeError("Logger has not been initialized. Call init_logger() first.")
        return MilesLogger.try_import_loguru()

    @staticmethod
    def init_logger(
        log_dir: Path = Path("logs"),
        label: str = None,
        serialize: bool = True,
        pretty_console: bool = True,
        level: str = "INFO",
    ):
        loguru = MilesLogger.try_import_loguru()

        if MilesLogger._configured:
            return loguru

        log_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")
        label = f"_{label}" if label else ""
        log_path = log_dir / f"{timestamp}{label}.log"

        if pretty_console:
            loguru.add(sys.stderr, level=level, enqueue=True)

        loguru.add(log_path, level=level, serialize=serialize, rotation="10 MB", enqueue=True)

        MilesLogger._logger = loguru  # ← Add this line
        MilesLogger._current_log_path = log_path
        MilesLogger._configured = True
        return loguru

    @staticmethod
    def get_logger():
        if not MilesLogger._configured:
            return MilesLogger.init_logger()
        return MilesLogger._logger

    @staticmethod
    def reset_logger():
        loguru = MilesLogger.try_import_loguru()
        loguru.remove()
        MilesLogger._current_log_path = None
        MilesLogger._configured = False
        MilesLogger._logger = None

log = MilesLogger.get_logger()
log_path = MilesLogger._current_log_path
log_exists = MilesLogger._configured

@pytest.fixture(autouse=True)
def cleanup_logger():
    MilesLogger.reset_logger()
    yield
    MilesLogger.reset_logger()

def test_logger_initializes_and_creates_log_file(tmp_path):
    logger = MilesLogger.init_logger(log_dir=tmp_path, label="test_log", serialize=False)
    assert MilesLogger._configured is True
    assert MilesLogger._logger is logger
    log_path = MilesLogger._current_log_path
    assert log_path.exists()
    assert log_path.suffix == ".log"
    assert "test_log" in log_path.name

def test_logger_get_logger_returns_cached_instance(tmp_path):
    logger1 = MilesLogger.init_logger(log_dir=tmp_path, label="one", serialize=False)
    logger2 = MilesLogger.get_logger()
    assert logger1 is logger2
    assert MilesLogger._configured is True

def test_logger_reset_resets_state(tmp_path):
    MilesLogger.init_logger(log_dir=tmp_path, label="reset_test", serialize=False)
    MilesLogger.reset_logger()
    assert MilesLogger._configured is False
    assert MilesLogger._current_log_path is None
    assert MilesLogger._logger is None

def test_logger_get_loguru_raises_before_init():
    with pytest.raises(RuntimeError):
        MilesLogger.get_loguru()

def test_logger_get_logger_autoinits(tmp_path, monkeypatch):
    called = {"init": False}

    def mock_init_logger(*args, **kwargs):
        called["init"] = True
        return MilesLogger.try_import_loguru()

    monkeypatch.setattr(MilesLogger, "init_logger", mock_init_logger)
    _ = MilesLogger.get_logger()
    assert called["init"] is True

def test_log_file_is_writable(tmp_path):
    logger = MilesLogger.init_logger(log_dir=tmp_path, label="writable", serialize=False)
    logger.info("Test message")
    logger.complete()  # ✅ flushes all logs before we read the file
    log_path = MilesLogger._current_log_path
    with open(log_path, "r", encoding="utf-8") as f:
        contents = f.read()
    assert "Test message" in contents
