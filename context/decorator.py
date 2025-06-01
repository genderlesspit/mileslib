import builtins
import inspect
import time
import uuid
from datetime import time
from functools import wraps
from pathlib import Path
from typing import Optional, Union, Callable, Any, List

import click

from util import milesutil as mu
from context.config import Config
from context.envloader import EnvLoader as env
from context.logger import Logger, log_func


class Decorator:
    """
    MilesLib-compatible decorator with full log capture for print/echo,
    retry/fix, timed, safe modes, and hierarchical func-name context.
    """

    @staticmethod
    def mileslib(
            *,
            retry: bool = False,
            fix: Optional[Union[callable, list]] = None,
            timed: bool = True,
            logged: bool = True,
            safe: bool = True,
            env: bool = True,
            callback: Optional[str] = None,
            label: Optional[str] = None,
    ):
        def decorator(fn):
            # Unwrap staticmethod/classmethod
            if isinstance(fn, (staticmethod, classmethod)):
                fn = fn.__func__
            uid = uuid.uuid4().hex[:8]

            @wraps(fn)
            def wrapper(*args, **kwargs):
                name = fn.__qualname__
                with log_func(name):
                    log = Decorator._init_logger()
                    Decorator._hijack_stdout(log, name)
                    Decorator._inject_globals(fn, log)

                    try:
                        if env:
                            Decorator._apply_env_overrides(log, name)
                        Decorator._inject_env_kwargs(fn, kwargs, log)

                        core_fn = Decorator._build_core(
                            fn, args, kwargs, timed, logged, callback, log
                        )

                        if retry:
                            return Decorator._execute_retry(core_fn, fix, name, log)
                        if safe:
                            return Decorator._execute_safe(core_fn, name, log)

                    except Exception as e:
                        log.exception(f"[{name}] ❌ Uncaught exception: {e}")
                        raise RuntimeError(f"[{name}] ❌ Crashed with: {e}") from e

            return wrapper

        return decorator

    # ─── Helper Methods ─────────────────────────────────────────────────────────

    @staticmethod
    def _init_logger() -> "import loguru:":
        """
        Initialize the loguru logger (once) and return it.
        """
        # defined variables
        logger = None

        # logic
        Logger.init_logger()
        logger = Logger.get_loguru()
        logger.debug("[Decorator] Logger initialized")
        return logger

    @staticmethod
    def _hijack_stdout(log, name: str):
        """
        Redirect builtins.print and click.echo to the logger, tracking depth.
        """
        # logic
        depth = getattr(log_func, "_hijack_depth", 0)
        log.debug(f"[{name}] Hijack stdout (depth={depth})")

        if depth == 0:
            log_func._orig_print = builtins.print
            log_func._orig_echo = click.echo
            builtins.print = lambda *a, **k: log.info("{}", " ".join(map(str, a)))
            click.echo = lambda *a, **k: log.info("{}", " ".join(map(str, a)))
        log_func._hijack_depth = depth + 1
        log.debug(f"[{name}] Hijack depth now {log_func._hijack_depth}")

    @staticmethod
    def _restore_stdout(name: str):
        """
        Restore builtins.print and click.echo to their originals.
        """
        log = Logger.get_loguru()
        depth = getattr(log_func, "_hijack_depth", 1) - 1
        log.debug(f"[{name}] Restore stdout (depth={depth})")

        if depth == 0:
            builtins.print = log_func._orig_print
            click.echo = log_func._orig_echo
            delattr(log_func, "_hijack_depth")
            delattr(log_func, "_orig_print")
            delattr(log_func, "_orig_echo")
        else:
            log_func._hijack_depth = depth

        log.debug(f"[{name}] Hijack depth now {depth}")

    @staticmethod
    def _apply_env_overrides(log, name: str):
        """
        Load .env and apply Config overrides, warning on failure.
        """
        # logic
        log.debug(f"[{name}] Applying .env + config overrides")
        env.load_env()
        try:
            Config.apply_env(overwrite=True)
        except Exception as e:
            log.warning(f"[{name}] Override failure: {e}")

    @staticmethod
    def _inject_env_kwargs(fn, kwargs: dict, log):
        """
        Inject any cached env vars into kwargs if the function signature accepts them.
        """
        # defined variables
        sig = inspect.signature(fn)
        env_cache = env._cache

        # logic
        for k, v in env_cache.items():
            if k in sig.parameters and k not in kwargs:
                kwargs[k] = v
                log.debug(f"[{fn.__qualname__}] Injected env var {k}={v}")

    @staticmethod
    def _inject_globals(fn, log):
        """
        Injects logger, shared resources, and all uppercase env vars into fn.__globals__.

        Overwrites existing globals for dynamic reconfiguration.

        Only injects if:
        - The key is a valid Python identifier (k.isidentifier())
        - The key is ALL UPPERCASE
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
                old = fn.__globals__.get(k, "<unset>")
                fn.__globals__[k] = v
                log.debug(f"[{fn.__qualname__}] Overwrote global {k}: {old} -> {v}")
        except AttributeError:
            log.warning(f"[{fn.__qualname__}] No __globals__ found; skipping global injection")

    @staticmethod
    def _build_core(fn, args: tuple, kwargs: dict, timed: bool, logged: bool, callback: Optional[str],
                    log) -> Callable:
        """
        Construct the actual core call logic, including timing, logging, and callbacks.
        """

        # defined sub-function
        def _core():
            # logic
            if logged:
                log.info(f"[{fn.__qualname__}] Calling with args={args}, kwargs={kwargs}")
            if timed:
                start = time.perf_counter()

            else:
                result = fn(*args, **kwargs)

            if timed:
                dur = time.perf_counter() - start
                log.info(f"[{fn.__qualname__}] Completed in {dur:.3f}s")

            return result

        log.debug(f"[{fn.__qualname__}] Core function constructed")
        return _core

    @staticmethod
    def _execute_retry(core_fn: Callable, fix, name: str, log):
        """
        Run core_fn with retry/fix logic.
        """
        # logic
        log.debug(f"[{name}] Executing with retry (fix={fix})")
        return Decorator._attempt(core_fn, fix, name)

    @staticmethod
    def _execute_safe(core_fn: Callable, name: str, log):
        """
        Run core_fn in safe mode, catching exceptions and returning None on failure.
        """
        # logic
        log.debug(f"[{name}] Executing in safe mode")
        try:
            return core_fn()
        except Exception as e:
            log.exception(f"[{name}] Exception in safe mode: {e}")
            return None

    @staticmethod
    def _attempt(core_fn: Callable[[], Any],
                 fix: Optional[Union[Callable[[], None], List[Callable[[], None]]]],
                 label: str) -> Any:
        """
        Runs core_fn with retries and optional fix logic using StaticMethods.ErrorHandling.
        """
        if fix:
            return mu.recall(core_fn, fix)
        return mu.attempt(core_fn, fix=None, label=label)

def shim(fn: Optional[Callable] = None, **kwargs):
    """
    Supports both @mileslib and @mileslib(...) usage.
    """
    if fn is not None and callable(fn) and not kwargs:
        return Decorator.mileslib()(fn)
    elif fn is None or callable(fn):
        return Decorator.mileslib(**kwargs)
    else:
        raise TypeError("Invalid usage of @mileslib")

mileslib = shim
ROOT = Path(env.get("global_root"))