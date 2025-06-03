import json
import sys
import time
import threading
import itertools
import subprocess
import logging
from typing import Callable, Optional

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
    cmd: list[str],
    *,
    capture_output: bool = True,
    ignore_errors: dict[str, list[str]] | None = None,
    fallbacks: dict[str, Callable[[], None]] | None = None,
    force_refresh: bool = False
) -> dict:
    """
    Run Azure CLI commands with a spinner, caching, and default Python logging.

    All defined variables:
        resolved_cmd: list[str]
        expect_json: bool
        full_cmd: list[str]
        full_cmd_str: str
        proc: subprocess.Popen
        stdout: str
        stderr: str
        spinner_thread: threading.Thread
        spinner_stop_event: threading.Event

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

    Logic:
        1. Ensure Azure CLI dependency is present (once).
        2. Resolve path to 'az' executable.
        3. Determine if JSON output is expected.
        4. Build the final command (adding '--output json' if needed).
        5. Check cache (unless force_refresh=True).
        6. Start a spinner thread.
        7. Execute the subprocess and wait, showing spinner.
        8. On success, parse JSON or return {}.
        9. Store result in cache.
        10. On failure, attempt fallbacks, ignore rules, or exit.
    """
    # Defined variables
    resolved_cmd: list[str]
    expect_json: bool
    full_cmd: list[str]
    full_cmd_str: str
    proc: subprocess.Popen
    stdout: str
    stderr: str
    spinner_thread: threading.Thread
    spinner_stop_event: threading.Event

    # Sub-functions
    def _nuke(reason: str, code: int = 99) -> None:
        """
        Log a fatal error and exit the process after showing a countdown spinner.
        """
        logger.error(f"[run_az] ❌ {reason}")
        logger.error("[run_az] 💡 Try restarting your terminal or IDE to reload PATH.")
        logger.error(f"[run_az] ☢️  Nuking program in 10 seconds...")
        local_spinner = itertools.cycle("|/-\\")
        for i in range(20):
            sys.stdout.write(f"\r[run_az] {next(local_spinner)} {10 - i // 2}s remaining... ")
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

    def _resolve_command_path(original_cmd: list[str]) -> list[str]:
        """
        Resolve the actual path to the 'az' executable. If found, replace original_cmd[0].
        """
        from util.milessubprocess.cmd import CMD
        resolved = CMD.which(original_cmd[0])
        if resolved:
            return [resolved] + original_cmd[1:]
        return original_cmd.copy()

    def _should_expect_json(cmd_list: list[str], capture_flag: bool) -> bool:
        """
        Determine whether to append '--output json' based on command and capture_output.
        """
        joined = " ".join(cmd_list).lower()
        if not capture_flag:
            return False
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

    def _execute_with_spinner(cmd_list: list[str], capture_flag: bool) -> tuple[str, str]:
        """
        Launch the subprocess with Popen, show spinner while waiting, and return (stdout, stderr).

        Returns:
            stdout: str (decoded, possibly empty)
            stderr: str (decoded, possibly empty)
        """
        nonlocal spinner_thread, spinner_stop_event

        stdout_pipe = subprocess.PIPE if capture_flag else None
        stderr_pipe = subprocess.PIPE if capture_flag else None

        try:
            proc = subprocess.Popen(
                cmd_list,
                stdout=stdout_pipe,
                stderr=stderr_pipe,
                text=True,
                shell=False
            )
        except FileNotFoundError as fnf:
            _nuke(f"Failed to start Azure CLI process: {fnf}", code=99)

        spinner_stop_event = threading.Event()
        spinner_thread = threading.Thread(target=_start_spinner, args=(spinner_stop_event,), daemon=True)
        spinner_thread.start()

        stdout_data, stderr_data = proc.communicate()
        return stdout_data or "", stderr_data or ""

    def _process_success(raw_stdout: str, expect_flag: bool) -> dict:
        """
        Process the subprocess output on success. Parse JSON if expected.
        """
        if not raw_stdout.strip():
            if expect_flag:
                _nuke("Azure CLI returned no stdout (possibly non-JSON or interactive mode)", code=97)
            else:
                logger.info("[run_az] ✅ Completed interactive command (no JSON expected).")
                return {}
        if expect_flag:
            try:
                return json.loads(raw_stdout.strip())
            except json.JSONDecodeError as jde:
                _nuke(f"Failed to parse JSON: {jde}", code=94)
        return {}

    def _handle_subprocess_error(stderr_text: str, returncode: int, cmd_list: list[str]) -> dict:
        """
        Handle errors by checking for fallbacks and ignore rules or nuke the process.
        """
        lower_err = stderr_text.lower()

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
                            force_refresh=force_refresh
                        )
                    except Exception as fallback_ex:
                        _nuke(f"Fallback for '{key}' failed: {fallback_ex}", code=95)

        if ignore_errors:
            for key, substrings in ignore_errors.items():
                for substr in substrings:
                    if substr.lower() in lower_err:
                        logger.info(f"[run_az] ℹ️ Ignoring '{substr}' error for '{key}'. Continuing.")
                        return {}

        _nuke(f"Azure CLI failed (code {returncode}): {' '.join(cmd_list)} ↳ {lower_err}", code=96)

    def _check_cached_runs(full_cmd_list: list[str], force_refresh_flag: bool) -> Optional[dict]:
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
        _stop_spinner(spinner_stop_event, spinner_thread)
        result = _process_success(stdout, expect_json)
        entry_key = full_cmd_str
        CachedRuns.store_output(entry_key, full_cmd_str, result)
        return result
    except subprocess.CalledProcessError as ex:
        _stop_spinner(spinner_stop_event, spinner_thread)
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
    project: str,
    *,
    capture_output: bool = True,
    ignore_errors: dict[str, list[str]] | None = None,
    fallbacks: dict[str, Callable[[], None]] | None = None,
    force_refresh: bool = False
) -> dict:
    """
    Create a new Azure AD application with the given display name.

    All defined variables:
        cmd_list: list[str]
        full_cmd_str: str
        result: dict

    Logic:
        1. Validate 'project' is a non-empty string for display name.
        2. Build the Azure CLI command for 'az ad app create'.
        3. Invoke run_az with provided flags.
        4. Return parsed JSON or {}.
    """
    if not isinstance(project, str) or not project.strip():
        raise ValueError("app_create: 'project' must be a non-empty string for display name")

    cmd_list = ["az", "ad", "app", "create", "--display-name", project]
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

def get_all_subscriptions(
    *,
    capture_output: bool = True,
    ignore_errors: dict[str, list[str]] | None = None,
    fallbacks: dict[str, Callable[[], None]] | None = None,
    force_refresh: bool = False
) -> dict:
    """
    Retrieve all Azure subscriptions for the current account.

    All defined variables:
        cmd_list: list[str]
        result: dict

    Logic:
        1. Build the Azure CLI command for 'az account list'.
        2. Invoke run_az with caching, spinner, and the provided flags.
        3. Return parsed JSON (list of subscriptions).
        4. On exception, log and re-raise.

    Parameters:
        capture_output (bool): If False, run interactively (no JSON parsing).
        ignore_errors (dict[str, list[str]]|None): Error substrings to ignore.
        fallbacks (dict[str, Callable]|None): Handlers to invoke on specific errors.
        force_refresh (bool): If True, bypass cache and re-run the command.

    Returns:
        dict: Parsed JSON list of subscriptions (or {} if non-JSON).
    """
    # Build the CLI command
    cmd_list = ["az", "account", "list"]

    try:
        result = run_az(
            cmd_list,
            capture_output=capture_output,
            ignore_errors=ignore_errors,
            fallbacks=fallbacks,
            force_refresh=force_refresh
        )
        logger.info("[Azure.get_all_subscriptions] Retrieved all subscriptions")
        return result
    except Exception as ex:
        logger.error(f"[Azure.get_all_subscriptions] Failed to list subscriptions: {ex}")
        raise

def rg_exists(
    rg_name: str,
    *,
    capture_output: bool = True,
    ignore_errors: dict[str, list[str]] | None = None,
    fallbacks: dict[str, Callable[[], None]] | None = None,
    force_refresh: bool = False
) -> bool:
    """
    Check if the given resource group exists.

    All defined variables:
        cmd_list: list[str]
        result: bool | str | dict

    Logic:
        1. Validate 'rg_name' is a non‐empty string.
        2. Build the Azure CLI command for 'az group exists'.
        3. Invoke run_az with JSON output expected.
        4. Interpret the return value (bool or "true"/"false" string).
        5. Return True if it exists, False otherwise.
    """
    if not isinstance(rg_name, str) or not rg_name.strip():
        raise ValueError("AzureResourceGroup.exists: 'rg_name' must be a non-empty string")

    cmd_list = ["az", "group", "exists", "--name", rg_name]
    try:
        raw_result = run_az(
            cmd_list,
            capture_output=capture_output,
            ignore_errors=ignore_errors,
            fallbacks=fallbacks,
            force_refresh=force_refresh
        )
        # run_az with "--output json" will parse "true"/"false" into a Python bool
        if isinstance(raw_result, bool):
            return raw_result
        # In the unlikely event run_az returns a string (non-JSON), interpret it
        if isinstance(raw_result, str):
            return raw_result.strip().lower() == "true"
        # If run_az returned a dict (unexpected), attempt to extract boolean
        if isinstance(raw_result, dict):
            # Some Azure CLI commands might wrap boolean in a key, but 'az group exists' returns raw bool
            # Default to False if structure is unexpected
            logger.warning(f"[AzureResourceGroup.exists] Unexpected dict result for '{rg_name}': {raw_result}")
            return False
        return False
    except Exception as ex:
        logger.error(f"[AzureResourceGroup.exists] Error checking existence of '{rg_name}': {ex}")
        raise

def rg_create(
    rg_name: str,
    location: str,
    *,
    capture_output: bool = True,
    ignore_errors: dict[str, list[str]] | None = None,
    fallbacks: dict[str, Callable[[], None]] | None = None,
    force_refresh: bool = False
) -> dict:
    """
    Create the resource group if it doesn't exist.

    All defined variables:
        cmd_list: list[str]
        result: dict

    Logic:
        1. Validate 'rg_name' and 'location' are non-empty strings.
        2. If exists(...) returns True, log and return empty dict.
        3. Build the Azure CLI command for 'az group create'.
        4. Invoke run_az with JSON output expected.
        5. Return the parsed JSON response (resource group properties).
    """
    if not isinstance(rg_name, str) or not rg_name.strip():
        raise ValueError("AzureResourceGroup.create: 'rg_name' must be a non-empty string")
    if not isinstance(location, str) or not location.strip():
        raise ValueError("AzureResourceGroup.create: 'location' must be a non-empty string")

    # Check existence first (force_refresh=False to allow caching if recently checked)
    try:
        if rg_exists(rg_name, capture_output=True, force_refresh=force_refresh):
            logger.info(f"[AzureResourceGroup.create] Resource group '{rg_name}' already exists; skipping creation.")
            return {}
    except Exception:
        # If exists(...) fails (e.g., transient error), proceed to attempt creation
        logger.warning(f"[AzureResourceGroup.create] Could not confirm existence of '{rg_name}', attempting to create anyway.")

    print(f"[AzureResourceGroup] 🛠️ Creating resource group '{rg_name}' in region '{location}'...")
    cmd_list = [
        "az", "group", "create",
        "--name", rg_name,
        "--location", location
    ]
    try:
        result = run_az(
            cmd_list,
            capture_output=capture_output,
            ignore_errors=ignore_errors,
            fallbacks=fallbacks,
            force_refresh=force_refresh
        )
        logger.info(f"[AzureResourceGroup.create] Created resource group '{rg_name}' in '{location}'")
        return result
    except Exception as ex:
        logger.error(f"[AzureResourceGroup.create] Failed to create resource group '{rg_name}': {ex}")
        raise

def region_init(
    rg_name: str,
    *,
    capture_output: bool = True,
    ignore_errors: dict[str, list[str]] | None = None,
    fallbacks: dict[str, Callable[[], None]] | None = None,
    force_refresh: bool = False
) -> str:
    """
    Resolve the Azure region for a given project by inspecting its resource group, then cache it.

    All defined variables:
        rg: str
        data: dict
        region: str

    Logic:
        1. Validate 'project' is a non-empty string.
        2. Retrieve the resource group name via AzureResourceGroup.get(project).
        3. Call `az group show --name <rg>` to get resource group details.
        4. Extract 'location' from the JSON response.
        5. If location is missing or empty, raise RuntimeError.
        6. Cache the region under key "{project}.AZURE_REGION" via mc.cache.set.
        7. Print resolved region and return it.

    Parameters:
        project (str): The project namespace used to look up its resource group.
        capture_output (bool): Whether to capture stdout/stderr (JSON expected).
        ignore_errors (dict[str, list[str]]|None): Substrings to ignore in stderr.
        fallbacks (dict[str, Callable]|None): Fallback handlers for specific errors.
        force_refresh (bool): If True, bypass any caching in run_az.

    Returns:
        str: The Azure region string (e.g., "eastus").
    """
    # 1) Deprecated
    # 2) Get resource group name for this project
    rg = rg_name
    if not isinstance(rg, str) or not rg.strip():
        raise RuntimeError(f"[AzureRegion] Invalid resource group returned for: {rg!r}")

    # 3) Query Azure for resource group details
    try:
        data = run_az(
            ["az", "group", "show", "--name", rg],
            capture_output=capture_output,
            ignore_errors=ignore_errors,
            fallbacks=fallbacks,
            force_refresh=force_refresh
        )
    except Exception as ex:
        raise RuntimeError(f"[AzureRegion] Could not resolve region from resource group '{rg}': {ex}")

    # 4) Extract 'location'
    region = ""
    if isinstance(data, dict):
        region = data.get("location", "")
        if isinstance(region, str):
            region = region.strip()
    if not region:
        raise RuntimeError(f"[AzureRegion] Region missing from 'az group show' response for '{rg}': {data!r}")

    # 5) Inform user and return
    print(f"[AzureRegion] Region resolved from resource group '{rg}': {region}")
    return region