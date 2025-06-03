import itertools
import json
import logging
import os
import subprocess
import sys
import threading
import time
from typing import Callable, Optional, List, Dict

from util.milesprocess import run as miles_run  # <-- import the convenience alias
from util.milessubprocess.cmd import CMD

logger = logging.getLogger(__name__)


class CachedRuns:
    """
    Simple in‐process cache for Azure CLI command outputs.
    Follows schema:
      cached_runs = {
          "entry": {
              "full_cmd": "",
              "output": {}
          }
      }
      ensured_azure_cli = False
    """
    cached_runs: dict[str, dict[str, str | dict]] = {
        "entry": {
            "full_cmd": "",
            "output": {}
        }
    }
    ensured_azure_cli: bool = False

    @staticmethod
    def get_cached_output(full_cmd_str: str) -> Optional[dict]:
        """
        Return cached output if the command was previously run (matching full_cmd).
        """
        for entry_name, entry in CachedRuns.cached_runs.items():
            if entry.get("full_cmd") == full_cmd_str:
                logger.debug(f"[CachedRuns] Cache hit under key '{entry_name}' for '{full_cmd_str}'")
                return entry.get("output", {})
        logger.debug(f"[CachedRuns] Cache miss for '{full_cmd_str}'")
        return None

    @staticmethod
    def store_output(entry_name: str, full_cmd_str: str, output: dict) -> None:
        """
        Store command result in the cache under a given entry name.
        """
        CachedRuns.cached_runs[entry_name] = {
            "full_cmd": full_cmd_str,
            "output": output
        }
        logger.debug(f"[CachedRuns] Stored output for '{entry_name}': {full_cmd_str}")


def run_az(
        cmd: List[str],
        *,
        capture_output: bool = True,
        ignore_errors: Dict[str, List[str]] | None = None,
        fallbacks: Dict[str, Callable[[], None]] | None = None,
        force_refresh: bool = False,
        json_override: bool | None = None
) -> dict:
    """
    Run Azure CLI commands with a spinner, caching, authentication fallback, and Python logging.

    All defined variables:
        resolved_cmd: List[str]
        expect_json: bool
        full_cmd: List[str]
        full_cmd_str: str
        completed: subprocess.CompletedProcess
        stdout: str
        stderr: str
        spinner_thread: threading.Thread
        spinner_stop_event: threading.Event
        auth_retry_done: bool

    All defined sub-functions:
        _nuke
        _ensure_azure_cli
        _resolve_command_path
        _should_expect_json
        _start_spinner
        _stop_spinner
        _execute_with_spinner
        _process_success
        _handle_subprocess_error
        _check_cached_runs
        _auth_fallback

    Logic:
        1. Ensure Azure CLI dependency is present (once).
        2. Resolve path to 'az' executable.
        3. Determine if JSON output is expected.
        4. Build the final command (adding '--output json' if needed).
        5. Check cache (unless force_refresh=True).
        6. Start a spinner thread.
        7. Execute the subprocess via MilesProcess.Runner.run(...) with global shell.
        8. On success, parse JSON or print raw stdout & return {}.
        9. Store result in cache.
       10. On failure, if 'Status_AccountUnusable' appears in stderr and we haven't retried auth yet:
             a. Run `_auth_fallback()` to clear tokens and re-login.
             b. Retry the original CLI command once.
        11. If still failing or a different error, proceed to ignore/fallback rules or nuke.
    """
    # Defined variables
    resolved_cmd: List[str]
    expect_json: bool
    full_cmd: List[str]
    full_cmd_str: str
    completed = None  # type: Optional[subprocess.CompletedProcess]
    stdout: str
    stderr: str
    spinner_thread: threading.Thread
    spinner_stop_event: threading.Event
    auth_retry_done: bool = False  # ensure we reauth only once

    # Sub-functions
    def _nuke(reason: str, code: int = 99) -> None:
        """
        Log a fatal error and exit the process after showing a countdown spinner.
        """
        logger.error(f"[run_az] ❌ {reason}")
        logger.error("[run_az] 💡 Try restarting your terminal or IDE to reload PATH.")
        logger.error(f"[run_az] ☢️  Nuking program in 10 seconds...")
        spinner = itertools.cycle("|/-\\")
        for i in range(20):
            sys.stdout.write(f"\r[run_az] {next(spinner)} {10 - i // 2}s remaining... ")
            sys.stdout.flush()
            time.sleep(0.5)
        print()
        logger.error("[run_az] 💥 Boom.")
        sys.exit(code)

    def _ensure_azure_cli() -> None:
        """
        Verify that the Azure CLI ('az') dependency is installed. Only runs once.
        """
        from util import milesutil as mu
        if CachedRuns.ensured_azure_cli:
            return
        try:
            mu.Dependency.ensure("milesazure")
            CachedRuns.ensured_azure_cli = True
        except Exception as ex:
            _nuke(f"Azure CLI not detected: {ex}", code=98)

    def _resolve_command_path(original_cmd: List[str]) -> List[str]:
        """
        Resolve the actual path to the 'az' executable. If found, replace original_cmd[0].
        """
        resolved = CMD.which(original_cmd[0])
        if resolved:
            return [resolved] + original_cmd[1:]
        return original_cmd.copy()

    def _should_expect_json(cmd_list: List[str], capture_flag: bool) -> bool:
        """
        Determine whether to append '--output json' based on command and capture_output,
        or honor json_override when provided.
        """
        if json_override is not None:
            return json_override

        joined = " ".join(cmd_list).lower()
        if not capture_flag:
            return False
        # Don’t force JSON for interactive or login commands
        if "--use-device-code" in joined or " login" in joined or "account set" in joined:
            return False
        return True

    def _start_spinner(stop_event: threading.Event) -> None:
        """
        Display a spinner on stdout until stop_event is set.
        """
        spin = itertools.cycle("|/-\\")
        while not stop_event.is_set():
            sys.stdout.write(f"\r[run_az] {next(spin)} Running Azure CLI...")
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write("\r" + " " * 50 + "\r")
        sys.stdout.flush()

    def _stop_spinner(stop_event: threading.Event, thread: threading.Thread) -> None:
        """
        Signal the spinner thread to stop and wait for it to finish.
        """
        stop_event.set()
        thread.join()

    def _execute_with_spinner(cmd_list: List[str], capture_flag: bool) -> tuple[str, str]:
        """
        Execute the command via MilesProcess.Runner.run(..., shell=True, force_global_shell=True),
        while showing a spinner until it completes. Return (stdout, stderr) strings.
        """
        nonlocal spinner_thread, spinner_stop_event

        spinner_stop_event = threading.Event()
        spinner_thread = threading.Thread(target=_start_spinner, args=(spinner_stop_event,), daemon=True)
        spinner_thread.start()

        try:
            # Force use of global shell on Windows: shell=True, force_global_shell=True
            completed = miles_run(
                cmd_list,
                shell=True,
                capture_output=capture_flag,
                check=True,
                text=True,
                force_global_shell=True
            )
            stdout_data = completed.stdout or ""
            stderr_data = completed.stderr or ""
        except Exception:
            # Stop spinner and re-raise so caller can handle
            _stop_spinner(spinner_stop_event, spinner_thread)
            raise

        _stop_spinner(spinner_stop_event, spinner_thread)
        return stdout_data, stderr_data

    def _process_success(raw_stdout: str, expect_flag: bool) -> dict:
        """
        Process the subprocess output on success. Parse JSON if expected.
        If stdout is empty or not valid JSON, print raw stdout and return {}.
        """
        if not raw_stdout.strip():
            logger.warning("[run_az] ⚠️ Azure CLI returned empty stdout.")
            return {}

        if expect_flag:
            try:
                return json.loads(raw_stdout.strip())
            except json.JSONDecodeError as jde:
                logger.warning(f"[run_az] ⚠️ Expected JSON but got invalid output: {jde}")
                print("[run_az] 🔍 Raw stdout:\n" + raw_stdout.strip())
                return {}

        return {}

    def _auth_fallback() -> None:
        nonlocal auth_retry_done
        if auth_retry_done:
            _nuke("[run_az] ⚠️ Authentication retry already attempted.", code=95)
        auth_retry_done = True

        # 1) Try Service Principal first (same as before)…
        client_id = os.getenv("AZURE_CLIENT_ID")
        client_secret = os.getenv("AZURE_CLIENT_SECRET")
        tenant_id_env = os.getenv("AZURE_TENANT_ID")
        if client_id and client_secret and tenant_id_env:
            logger.info("[run_az][AuthFallback] Attempting Service Principal login.")
            try:
                # if SP-credentials exist, login non-interactively
                miles_run(
                    ["az", "login",
                     "--service-principal",
                     "--username", client_id,
                     "--password", client_secret,
                     "--tenant", tenant_id_env],
                    shell=True,
                    check=True,
                    text=True,
                    force_global_shell=True
                )
                return
            except Exception as sp_ex:
                logger.warning(f"[run_az][AuthFallback] SP login failed: {sp_ex}")
                # fall through to device-code below

        # 2) Clear any existing Azure CLI context
        logger.warning("[run_az][AuthFallback] Clearing any existing Azure CLI login state…")
        try:
            miles_run(
                ["az", "account", "clear"],
                shell=True,
                check=True,
                text=True,
                force_global_shell=True
            )
        except Exception as e:
            logger.warning(f"[run_az][AuthFallback] 'az account clear' failed: {e}")

        # 3) STOP the spinner (if it’s still running)
        try:
            spinner_stop_event.set()
            spinner_thread.join()
        except Exception:
            pass

        # 4) Now run device-code login WITHOUT capturing output, so that
        #    the “https://microsoft.com/devicelogin” URL and code appear on screen.
        logger.warning("[run_az][AuthFallback] Starting 'az login --use-device-code'…")
        try:
            subprocess.run(  # use subprocess.run directly so that stdout/stderr stream to console
                ["az", "login", "--use-device-code"],
                shell=True,
                check=True,
                text=True,
                # force_global_shell=True is internal to miles_run; for subprocess.run we'll rely on shell=True
            )
        except Exception as e:
            _nuke(f"[run_az][AuthFallback] 'az login --use-device-code' failed: {e}", code=96)

        # 5) Once user has completed device-code flow, we can re-enable the spinner logic
        #    or simply proceed to grab account info normally:

        logger.warning("[run_az][AuthFallback] Fetching account details via 'az account show'…")
        try:
            acct_info = run_az(
                ["az", "account", "show"],
                capture_output=True,
                ignore_errors=None,
                fallbacks=None,
                force_refresh=True,
                json_override=True
            )
        except Exception as e:
            _nuke(f"[run_az][AuthFallback] 'az account show' failed: {e}", code=97)

        sub_id = acct_info.get("id")
        tenant = acct_info.get("tenantId")
        if not sub_id or not tenant:
            _nuke("[run_az][AuthFallback] Could not read subscription ID or tenantId", code=98)

        logger.info(f"[run_az][AuthFallback] Caching subscription={sub_id} tenant={tenant}")
        CachedRuns.store_output("AZURE_SUBSCRIPTION_ID", sub_id, sub_id)
        CachedRuns.store_output("AZURE_TENANT_ID", tenant, tenant)

        # 6) Warm up Graph token (optional):
        logger.warning("[run_az][AuthFallback] Warming up Graph token…")
        try:
            miles_run(
                ["az", "account", "get-access-token", "--scope", "https://graph.microsoft.com/.default"],
                shell=True,
                check=True,
                text=True,
                force_global_shell=True
            )
        except Exception as e:
            logger.warning(f"[run_az][AuthFallback] 'get-access-token' failed: {e}")

    def _handle_subprocess_error(stderr_text: str, returncode: int, cmd_list: List[str]) -> dict:
        """
        Handle errors by checking for built-in auth fallback, plus any user-provided
        fallbacks or ignore rules; otherwise nuke.
        """
        lower_err = stderr_text.lower()

        # 1) Built-in auth fallback on "accountunusable"
        if "status_accountunusable" in lower_err or "accountunusable" in lower_err:
            logger.warning("[run_az] ⚠️ Detected 'Status_AccountUnusable'. Invoking auth fallback…")
            try:
                _auth_fallback()
                logger.info(f"[run_az] 🔁 Retrying original command: {' '.join(cmd_list)}")
                return run_az(
                    cmd_list,
                    capture_output=capture_output,
                    ignore_errors=ignore_errors,
                    fallbacks=fallbacks,
                    force_refresh=force_refresh,
                    json_override=json_override
                )
            except Exception as fallback_ex:
                _nuke(f"[run_az] Auth fallback failed: {fallback_ex}", code=95)

        # 2) User-defined fallbacks
        if fallbacks:
            for key, handler in fallbacks.items():
                if key.lower() in lower_err:
                    logger.warning(f"[run_az] ⚠️ Triggering fallback handler for '{key}'")
                    try:
                        handler()
                        logger.info(f"[run_az] 🔁 Retrying original command: {' '.join(cmd_list)}")
                        return run_az(
                            cmd_list,
                            capture_output=capture_output,
                            ignore_errors=ignore_errors,
                            fallbacks=fallbacks,
                            force_refresh=force_refresh,
                            json_override=json_override
                        )
                    except Exception as fallback_ex:
                        _nuke(f"[run_az] Fallback for '{key}' failed: {fallback_ex}", code=95)

        # 3) ignore_errors rules
        if ignore_errors:
            for key, substrings in ignore_errors.items():
                for substr in substrings:
                    if substr.lower() in lower_err:
                        logger.info(f"[run_az] ℹ️ Ignoring '{substr}' error for '{key}'. Continuing.")
                        return {}

    def _check_cached_runs(full_cmd_list: List[str], force_refresh_flag: bool) -> Optional[dict]:
        """
        Checks whether the command has already been run before (exact match on full_cmd_str).
        """
        full_cmd_str_local = " ".join(full_cmd_list)
        if force_refresh_flag:
            logger.debug(f"[run_az] Force refresh enabled; skipping cache for '{full_cmd_str_local}'")
            return None
        return CachedRuns.get_cached_output(full_cmd_str_local)

    # --- Logic begins here ---
    _ensure_azure_cli()

    resolved_cmd = _resolve_command_path(cmd)
    logger.info(f"[run_az] ▶ Running: {' '.join(resolved_cmd)}")

    expect_json = _should_expect_json(resolved_cmd, capture_output)
    full_cmd = resolved_cmd + (["--output", "json"] if expect_json else [])
    full_cmd_str = " ".join(full_cmd)

    cached = _check_cached_runs(full_cmd, force_refresh)
    if cached is not None:
        logger.info(f"[run_az] 💾 Using cached output for: {full_cmd_str}")
        return cached

    try:
        stdout, stderr = _execute_with_spinner(full_cmd, capture_output)
        result = _process_success(stdout, expect_json)
        entry_key = full_cmd_str
        CachedRuns.store_output(entry_key, full_cmd_str, result)
        return result
    except subprocess.CalledProcessError as ex:
        return _handle_subprocess_error(ex.stderr or "", ex.returncode, full_cmd)


# ─────────────────────────────────────────────────────────────────────────────
# CONVENIENCE FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def app_show(
        project: str,
        *,
        capture_output: bool = True,
        ignore_errors: dict[str, list[str]] | None = None,
        fallbacks: dict[str, Callable[[], None]] | None = None,
        force_refresh: bool = False
) -> dict:
    """
    Show an existing Azure AD application by its appId or objectId.

    All defined variables:
        cmd_list: list[str]
        full_cmd_str: str
        result: dict

    Logic:
        1. Validate 'project' is a non-empty string.
        2. Build the Azure CLI command for 'az ad app show'.
        3. Invoke run_az with provided flags.
        4. Return parsed JSON or {}.
    """
    if not isinstance(project, str) or not project.strip():
        raise ValueError("app_show: 'project' must be a non-empty string representing appId or objectId")

    cmd_list = ["az", "ad", "app", "show", "--id", project]
    full_cmd_str = " ".join(cmd_list + (["--output", "json"] if capture_output else []))

    logger.info(f"[app_show] ▶ Running: {full_cmd_str}")
    return run_az(
        cmd_list,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh
    )


def app_create(
        app_name: str,
        *,
        capture_output: bool = True,
        ignore_errors: dict[str, list[str]] | None = None,
        fallbacks: dict[str, Callable[[], None]] | None = None,
        force_refresh: bool = False
) -> dict:
    """
    Create a new Azure AD application with the given display name.
    """
    if not isinstance(app_name, str) or not app_name.strip():
        raise ValueError("app_create: 'project' must be a non-empty string for display name")

    cmd_list = ["az", "ad", "app", "create", "--display-name", app_name]
    full_cmd_str = " ".join(cmd_list + (["--output", "json"] if capture_output else []))

    logger.info(f"[app_create] ▶ Running: {full_cmd_str}")
    return run_az(
        cmd_list,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh
    )

def sp_show(
        app_id: str,
        *,
        capture_output: bool = True,
        ignore_errors: dict[str, list[str]] | None = None,
        fallbacks: dict[str, Callable[[], None]] | None = None,
        force_refresh: bool = False
) -> dict:
    """
    Show an existing Azure AD service principal by its appId.

    All defined variables:
        cmd_list: list[str]
        full_cmd_str: str
        result: dict

    Logic:
        1. Validate 'app_id' is a non-empty string.
        2. Build the Azure CLI command for 'az ad sp show'.
        3. Invoke run_az with provided flags.
        4. Return parsed JSON or {}.
    """
    if not isinstance(app_id, str) or not app_id.strip():
        raise ValueError("sp_show: 'app_id' must be a non-empty string representing the application ID")

    cmd_list = ["az", "ad", "sp", "show", "--id", app_id]
    full_cmd_str = " ".join(cmd_list + (["--output", "json"] if capture_output else []))

    logger.info(f"[sp_show] ▶ Running: {full_cmd_str}")
    return run_az(
        cmd_list,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh
    )


def sp_create(
        app_id: str,
        *,
        capture_output: bool = True,
        ignore_errors: dict[str, list[str]] | None = None,
        fallbacks: dict[str, Callable[[], None]] | None = None,
        force_refresh: bool = False
) -> dict:
    """
    Create a new Azure AD service principal for the given appId.

    All defined variables:
        cmd_list: list[str]
        full_cmd_str: str
        result: dict

    Logic:
        1. Validate 'app_id' is a non-empty string.
        2. Build the Azure CLI command for 'az ad sp create'.
        3. Invoke run_az with provided flags.
        4. Return parsed JSON or {}.
    """
    if not isinstance(app_id, str) or not app_id.strip():
        raise ValueError("sp_create: 'app_id' must be a non-empty string representing the application ID")

    cmd_list = ["az", "ad", "sp", "create", "--id", app_id]
    full_cmd_str = " ".join(cmd_list + (["--output", "json"] if capture_output else []))

    logger.info(f"[sp_create] ▶ Running: {full_cmd_str}")
    return run_az(
        cmd_list,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh
    )

def vault_show(
        name: str,
        *,
        capture_output: bool = True,
        ignore_errors: dict[str, list[str]] | None = None,
        fallbacks: dict[str, Callable[[], None]] | None = None,
        force_refresh: bool = False
) -> dict:
    """
    Show an existing Azure Key Vault by its name.

    All defined variables:
        cmd_list: list[str]
        full_cmd_str: str
        result: dict

    Logic:
        1. Validate 'name' is a non-empty string for vault name.
        2. Build the Azure CLI command for 'az keyvault show'.
        3. Invoke run_az with provided flags.
        4. Return parsed JSON or {}.
    """
    if not isinstance(name, str) or not name.strip():
        raise ValueError("vault_show: 'name' must be a non-empty string for vault name")

    cmd_list = ["az", "keyvault", "show", "--name", name]
    full_cmd_str = " ".join(cmd_list + (["--output", "json"] if capture_output else []))

    logger.info(f"[vault_show] ▶ Running: {full_cmd_str}")
    return run_az(
        cmd_list,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh
    )


def vault_create(
        name: str,
        *,
        capture_output: bool = True,
        ignore_errors: dict[str, list[str]] | None = None,
        fallbacks: dict[str, Callable[[], None]] | None = None,
        force_refresh: bool = False
) -> dict:
    """
    Create a new Azure Key Vault with the given name.

    All defined variables:
        cmd_list: list[str]
        full_cmd_str: str
        result: dict

    Logic:
        1. Validate 'name' is a non-empty string for vault name.
        2. Build the Azure CLI command for 'az keyvault create'.
        3. Invoke run_az with provided flags.
        4. Return parsed JSON or {}.
    """
    if not isinstance(name, str) or not name.strip():
        raise ValueError("vault_create: 'name' must be a non-empty string for vault name")

    cmd_list = ["az", "keyvault", "create", "--name", name]
    full_cmd_str = " ".join(cmd_list + (["--output", "json"] if capture_output else []))

    logger.info(f"[vault_create] ▶ Running: {full_cmd_str}")
    return run_az(
        cmd_list,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh
    )


def postgres_show(
        name: str,
        *,
        capture_output: bool = True,
        ignore_errors: dict[str, list[str]] | None = None,
        fallbacks: dict[str, Callable[[], None]] | None = None,
        force_refresh: bool = False
) -> dict:
    """
    Show an existing Azure PostgreSQL Flexible Server by its name.

    All defined variables:
        cmd_list: list[str]
        full_cmd_str: str
        result: dict

    Logic:
        1. Validate 'name' is a non-empty string for server name.
        2. Build the Azure CLI command for 'az postgres flexible-server show'.
        3. Invoke run_az with provided flags.
        4. Return parsed JSON or {}.
    """
    if not isinstance(name, str) or not name.strip():
        raise ValueError("postgres_show: 'name' must be a non-empty string for server name")

    cmd_list = ["az", "postgres", "flexible-server", "show", "--name", name]
    full_cmd_str = " ".join(cmd_list + (["--output", "json"] if capture_output else []))

    logger.info(f"[postgres_show] ▶ Running: {full_cmd_str}")
    return run_az(
        cmd_list,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh
    )


def postgres_create(
        name: str,
        *,
        capture_output: bool = True,
        ignore_errors: dict[str, list[str]] | None = None,
        fallbacks: dict[str, Callable[[], None]] | None = None,
        force_refresh: bool = False
) -> dict:
    """
    Create a new Azure PostgreSQL Flexible Server with the given name.

    All defined variables:
        cmd_list: list[str]
        full_cmd_str: str
        result: dict

    Logic:
        1. Validate 'name' is a non-empty string for server name.
        2. Build the Azure CLI command for 'az postgres flexible-server create'.
        3. Invoke run_az with provided flags.
        4. Return parsed JSON or {}.
    """
    if not isinstance(name, str) or not name.strip():
        raise ValueError("postgres_create: 'name' must be a non-empty string for server name")

    cmd_list = ["az", "postgres", "flexible-server", "create", "--name", name]
    full_cmd_str = " ".join(cmd_list + (["--output", "json"] if capture_output else []))

    logger.info(f"[postgres_create] ▶ Running: {full_cmd_str}")
    return run_az(
        cmd_list,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh
    )
