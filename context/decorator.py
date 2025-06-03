import builtins
import inspect
import logging
import time
import uuid
from functools import wraps
from typing import Optional, Union, Callable, Any, List

import click

from util import milesutil as mu
from context.config import Config
from context.envloader import EnvLoader as env
from context.logger import Logger, log_func


class Decorator:
    """
    MilesLib-compatible decorator that captures:
      - builtins.print
      - click.echo
      - Python's standard logging (logging.getLogger(...).info, warning, error, etc.)
      - Retry/fix logic
      - Timing and safe modes
      - Hierarchical function-name context via log_func
    """

    @staticmethod
    def mileslib(
        *,
        retry: bool = False,
        fix: Optional[Union[Callable[[], None], List[Callable[[], None]]]] = None,
        timed: bool = True,
        logged: bool = True,
        safe: bool = True,
        env: bool = True,
        callback: Optional[str] = None,
        label: Optional[str] = None,
    ):
        """
        Decorator factory. Usage:

            @mileslib()                # defaults
            @mileslib(retry=True, fix=[...])
            def some_function(...):
                ...

        Parameters:
            retry (bool):            If True, wrap in retry logic via mu.attempt/mu.recall.
            fix (Callable or list):  One or more fix-functions to run before retrying.
            timed (bool):            If True, log execution duration.
            logged (bool):           If True, log entry/exit and args/kwargs.
            safe (bool):             If True, catch exceptions and return None.
            env (bool):              If True, load .env + Config.apply_env before calling.
            callback (str):          (Reserved) name of any callback to invoke afterward.
            label (str):             (Reserved) label for downstream instrumentation.
        """
        def decorator(fn):
            # If decorating a staticmethod/classmethod, unwrap to the underlying function
            if isinstance(fn, (staticmethod, classmethod)):
                fn = fn.__func__

            uid = uuid.uuid4().hex[:8]  # reserved for deeper context tagging

            @wraps(fn)
            def wrapper(*args, **kwargs):
                name = fn.__qualname__
                with log_func(name):
                    # Initialize Loguru logger
                    log = Decorator._init_logger()

                    # Hijack print/echo and Python's logging at first depth
                    Decorator._hijack_stdout_and_logging(log, name)

                    # Inject log and UPPERCASE env vars into fn.__globals__
                    Decorator._inject_globals(fn, log)

                    try:
                        # 1) Environment overrides (load .env, apply Config)
                        if env:
                            Decorator._apply_env_overrides(log, name)

                        # 2) Inject any cached env-vars into kwargs
                        Decorator._inject_env_kwargs(fn, kwargs, log)

                        # 3) Build the “core” function (with timing & logging)
                        core_fn = Decorator._build_core(fn, args, kwargs, timed, logged, callback, log)

                        # 4) Dispatch based on retry/safe flags:
                        if retry:
                            result = Decorator._execute_retry(core_fn, fix, name, log)
                        elif safe:
                            result = Decorator._execute_safe(core_fn, name, log)
                        else:
                            # If neither retry nor safe: run core directly and let exceptions bubble
                            result = core_fn()

                        # (Optional) callback logic could be inserted here if callback is provided.

                        return result

                    except Exception as e:
                        # Any exception not caught by “safe” will be logged and re-raised as RuntimeError
                        log.exception(f"[{name}] ❌ Uncaught exception: {e}")
                        raise RuntimeError(f"[{name}] ❌ Crashed with: {e}") from e

                    finally:
                        # Always restore original stdout/echo/logging regardless of success/failure
                        Decorator._restore_stdout_and_logging(name)

            return wrapper

        return decorator

    # ─── Helper Methods ─────────────────────────────────────────────────────────

    @staticmethod
    def _init_logger() -> Any:
        """
        Initialize the Loguru logger (once) and return it.
        """
        Logger.init_logger()
        log = Logger.get_loguru()
        log.debug("[Decorator] Logger initialized")
        return log

    @staticmethod
    def _hijack_stdout_and_logging(log: Any, name: str):
        """
        Redirect builtins.print, click.echo, and Python's root logger to Loguru,
        tracking nesting depth on log_func._hijack_depth.
        """
        depth = getattr(log_func, "_hijack_depth", 0)
        log.debug(f"[{name}] Hijack stdout & logging (depth={depth})")

        if depth == 0:
            # ==== 1) Save originals for print & click.echo ====
            log_func._orig_print = builtins.print
            log_func._orig_echo = click.echo

            # Override builtins.print and click.echo to send to Loguru
            builtins.print = lambda *a, **k: log.info("{}", " ".join(map(str, a)))
            click.echo = lambda *a, **k: log.info("{}", " ".join(map(str, a)))

            # ==== 2) Save original logging.root handlers & level ====
            log_func._orig_log_handlers = logging.root.handlers.copy()
            log_func._orig_log_level = logging.root.level

            # ==== 3) Create an InterceptHandler that forwards stdlib logging to Loguru,
            # capturing the originating function name (record.funcName) ====
            class InterceptHandler(logging.Handler):
                """
                A logging.Handler that takes each LogRecord and re-emits it via Loguru,
                including the original function name.
                """
                def emit(self, record: logging.LogRecord) -> None:
                    try:
                        level_no = record.levelno
                        message = record.getMessage()
                        origin_fn = record.funcName or "<unknown>"

                        # Prepend origin function name to the message
                        prefixed = f"[from {origin_fn}] {message}"

                        # Calculate depth so Loguru reports the correct caller
                        depth_offset = 2

                        log.opt(depth=depth_offset, exception=record.exc_info).log(
                            level_no, prefixed
                        )
                    except Exception:
                        # If something breaks inside our handler, fallback to original print
                        log_func._orig_print(f"[InterceptHandler] Failed to log record: {record}")

            # ==== 4) Replace root logger's handlers & set level to NOTSET so everything propagates ====
            logging.root.handlers = [InterceptHandler()]
            logging.root.setLevel(logging.NOTSET)

        # Increment nesting depth
        log_func._hijack_depth = depth + 1
        log.debug(f"[{name}] Hijack depth now {log_func._hijack_depth}")

    @staticmethod
    def _restore_stdout_and_logging(name: str):
        """
        Restore builtins.print, click.echo, and Python's root logger to their originals
        when exiting the outermost decorator context.
        """
        log = Logger.get_loguru()
        depth = getattr(log_func, "_hijack_depth", 1) - 1
        log.debug(f"[{name}] Restore stdout & logging (depth={depth})")

        if depth <= 0:
            # ==== 1) Restore print & click.echo originals ====
            builtins.print = log_func._orig_print
            click.echo = log_func._orig_echo

            # ==== 2) Restore logging.root handlers & level ====
            logging.root.handlers = log_func._orig_log_handlers
            logging.root.setLevel(log_func._orig_log_level)

            # ==== 3) Clean up attributes on log_func ====
            delattr(log_func, "_hijack_depth")
            delattr(log_func, "_orig_print")
            delattr(log_func, "_orig_echo")
            delattr(log_func, "_orig_log_handlers")
            delattr(log_func, "_orig_log_level")

            log.debug(f"[{name}] stdout/echo/logging restored to originals")
        else:
            # Still nested, just decrement depth counter
            log_func._hijack_depth = depth
            log.debug(f"[{name}] Hijack depth now {depth}")

    @staticmethod
    def _apply_env_overrides(log: Any, name: str):
        """
        Load .env and apply Config overrides, logging a warning on failure.
        """
        log.debug(f"[{name}] Applying .env + Config overrides")
        env.load_env()
        try:
            Config.apply_env(overwrite=True)
        except Exception as e:
            log.warning(f"[{name}] Override failure: {e}")

    @staticmethod
    def _inject_env_kwargs(fn: Callable, kwargs: dict, log: Any):
        """
        Inject any cached env-vars into kwargs if the function signature accepts them.
        """
        sig = inspect.signature(fn)
        env_cache = getattr(env, "_cache", {})  # defensive: if no _cache, use empty dict

        for k, v in env_cache.items():
            if k in sig.parameters and k not in kwargs:
                kwargs[k] = v
                log.debug(f"[{fn.__qualname__}] Injected env var {k}={v}")

    @staticmethod
    def _inject_globals(fn: Callable, log: Any):
        """
        Inject “log” and ALL-UPPERCASE env-vars into fn.__globals__ for dynamic reconfiguration.
        """
        try:
            injectables = {
                "log": log,
                **{
                    k: v
                    for k, v in env.load_env().items()
                    if k.isidentifier() and k.isupper()
                }
            }

            for k, v in injectables.items():
                old_val = fn.__globals__.get(k, "<unset>")
                fn.__globals__[k] = v
                log.debug(f"[{fn.__qualname__}] Overwrote global {k}: {old_val} -> {v}")

        except AttributeError:
            log.warning(f"[{fn.__qualname__}] No __globals__ found; skipping global injection")

    @staticmethod
    def _build_core(
        fn: Callable,
        args: tuple,
        kwargs: dict,
        timed: bool,
        logged: bool,
        callback: Optional[str],
        log: Any,
    ) -> Callable[[], Any]:
        """
        Construct a “core()” closure that handles:
          - logging entry (if logged=True)
          - timing (if timed=True)
          - actual function invocation
          - logging exit with duration (if timed=True)
        """
        def _core():
            result = None

            # Optional: log entry with arguments
            if logged:
                log.info(f"[{fn.__qualname__}] Calling with args={args}, kwargs={kwargs}")

            # If timing is enabled, record execution time
            if timed:
                start = time.perf_counter()
                result = fn(*args, **kwargs)
                duration = time.perf_counter() - start
                log.success(f"[{fn.__qualname__}] Completed in {duration:.3f}s")
            else:
                result = fn(*args, **kwargs)

            return result

        log.debug(f"[{fn.__qualname__}] Core function constructed")
        return _core

    @staticmethod
    def _execute_retry(
        core_fn: Callable[[], Any],
        fix: Optional[Union[Callable[[], None], List[Callable[[], None]]]],
        name: str,
        log: Any,
    ) -> Any:
        """
        Run core_fn with retry/fix logic via mu.attempt or mu.recall.
        """
        log.debug(f"[{name}] Executing with retry (fix={fix})")
        if fix:
            return mu.recall(core_fn, fix)
        return mu.attempt(core_fn, fix=None, label=name)

    @staticmethod
    def _execute_safe(fn: Callable, name: str, log: Any):
        """
        Run fn in “safe” mode: catch exceptions, log them, and return None.
        If DEBUG_MODE=1, also print stack trace.
        """
        try:
            return fn()
        except Exception as ex:
            log.error(f"[{name}] Exception in safe mode: {ex}")
            if env.get("DEBUG_MODE", required=False) == "1":
                import traceback
                traceback.print_exc()
            return None  # Return None instead of propagating


def shim(fn: Optional[Callable] = None, **kwargs):
    """
    Allows usage as either:

        @mileslib
        def foo(...):
            ...

    or

        @mileslib(retry=True, safe=False)
        def bar(...):
            ...

    If called with no args and directly on a function, delegate to mileslib() without kwargs.
    """
    if fn is not None and callable(fn) and not kwargs:
        return Decorator.mileslib()(fn)
    elif fn is None or callable(fn):
        return Decorator.mileslib(**kwargs)
    else:
        raise TypeError("Invalid usage of @mileslib")

mileslib = shim
