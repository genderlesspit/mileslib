import os
import logging as log

class Log:
    def __init__(self, mileslib, dir: str, quiet: bool = False):
        self.m = mileslib
        self.quiet = quiet
        self.dir = os.path.join(dir, "logs")
        self.filename = f"{self.m.timestamp}.txt"
        self.file, self.file_exists = self.m.exists("logs", self.filename, create_if_missing=True, quiet=True)
        self.initialized = False
        self.handler = None

        for handler in log.root.handlers[:]:
            log.root.removeHandler(handler)

        stream_handler = log.StreamHandler()
        stream_handler.setFormatter(log.Formatter(
            fmt='%(asctime)s - MILESLIB - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        log.getLogger().addHandler(stream_handler)
        log.getLogger().setLevel(log.INFO)

    def open_log(self):
        """Attach file handler for log file output."""
        if self.initialized or not self.dir:
            return

        os.makedirs(os.path.dirname(self.dir), exist_ok=True)

        self.handler = log.FileHandler(self.file, encoding="utf-8")
        self.handler.setFormatter(log.Formatter(
            fmt='%(asctime)s - MILESLIB - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        log.getLogger().addHandler(self.handler)

        self.info(f"Logging started at {self.file}")
        self.initialized = True

    def close_log(self):
        logger = log.getLogger()
        for handler in logger.handlers[:]:
            if isinstance(handler, log.FileHandler):
                handler.close()
                logger.removeHandler(handler)

    def info(self, message, quiet: bool = None):
        if quiet is False or (quiet is None and not self.quiet):
            log.info(message)

    def warning(self, message, quiet: bool = None):
        if quiet is False or (quiet is None and not self.quiet):
            log.warning(message)

    def error(self, message, quiet: bool = None):
        if quiet is False or (quiet is None and not self.quiet):
            log.warning(message)
