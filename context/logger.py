# ─── Hierarchical Call Stack Tracking ─────────────────────────────────────────
import contextvars
import sys
import uuid
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

# A context variable holding the current call‐stack as a list of function names
_call_stack = contextvars.ContextVar("_call_stack", default=[])

@contextmanager
def log_func(name: str):
    """
    Context manager to push/pop a function name onto the call stack.
    """
    stack = _call_stack.get()
    token = _call_stack.set(stack + [name])
    try:
        yield
    finally:
        _call_stack.reset(token)

def _enrich_record(record):
    """
    Loguru patch function: injects extra['func'] = dot-joined call stack.
    """
    stack = _call_stack.get()
    record["extra"]["func"] = ".".join(stack) if stack else ""
    return record


# ─── Logger Utility ───────────────────────────────────────────────────────────

class Logger:
    """
    Logger utility using loguru with UUID‐tagged session identity.
    Adds a patch to include hierarchical func names in every record.
    """

    _configured = False
    _uuid = None
    _logger = None
    _log_path = None
    _handler_ids = SimpleNamespace(file=None, console=None)

    @staticmethod
    def try_import_loguru():
        try:
            import loguru
        except ImportError as e:
            raise ImportError("loguru is required for Logger but not installed.") from e
        return loguru

    @staticmethod
    def init_logger(
            log_dir: Path = Path("logs"),
            label: str = None,
            serialize: bool = False,
            pretty_console: bool = True,
            level: str = "INFO",
    ):
        """
        Initialize the loguru logger with optional file and console output.
        Logs include a hierarchical func name from the call stack.
        """
        if Logger._configured:
            return Logger._logger

        loguru = Logger.try_import_loguru()
        logger = loguru.logger

        # One‐time configuration
        Logger._uuid = str(uuid.uuid4())
        Logger._configured = True

        # Ensure log directory exists
        log_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")
        suffix = f"__{label}" if label else f"__{Logger._uuid}"
        log_file = log_dir / f"{timestamp}{suffix}.log"
        Logger._log_path = log_file

        # Remove default handlers
        logger.remove()

        # Patch to enrich each record with our call stack (pass the function, don’t call it)
        logger = logger.patch(_enrich_record)

        # Format: time | LEVEL | func.hierarchy | message
        fmt = (
            "<green>{time:HH:mm:ss.SSS}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{extra[func]}</cyan> | "
            "{message}"
        )

        # Console handler
        if pretty_console:
            Logger._handler_ids.console = logger.add(
                sys.stderr, level=level, colorize=True, enqueue=True, format=fmt
            )

        # File handler
        Logger._handler_ids.file = logger.add(
            str(log_file), level=level, serialize=serialize, enqueue=True, format=fmt
        )
        # Initial debug
        logger.debug("[Logger Init] UUID={} → {}", Logger._uuid, log_file)
        Logger._logger = logger
        return logger

    @staticmethod
    def get_loguru():
        if not Logger._configured:
            raise RuntimeError("Logger has not been initialized.")
        return Logger._logger

    @staticmethod
    def diagnostics():
        print("Logger Diagnostics:")
        print(f"  UUID:       {Logger._uuid}")
        print(f"  Configured: {Logger._configured}")
        print(f"  Log Path:   {Logger._log_path}")
        print(f"  Handlers:   console={Logger._handler_ids.console}, file={Logger._handler_ids.file}")

    @staticmethod
    def reset():
        if Logger._logger:
            Logger._logger.remove()
        Logger._configured = False
        Logger._uuid = None
        Logger._logger = None
        Logger._log_path = None
        Logger._handler_ids = SimpleNamespace(file=None, console=None)
