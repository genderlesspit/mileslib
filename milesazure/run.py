import itertools
import json
import logging
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional
from typing import Callable, Union

from context.cache import cache_dict, cache
from mileslib import Runner
from util.milessubprocess.cmd import CMD

logger = logging.getLogger(__name__)

AZ_CACHE_NS = "azcli_cache"

class EnsuredCLI:
    ensured_cli = False

def run_az(
    cmd: List[str],
    *,
    capture_output: bool = True,
    ignore_errors: Optional[Dict[str, List[str]]] = None,
    fallbacks: Optional[Dict[str, Callable[[], None]]] = None,
    force_refresh: bool = False,
    json_override: Optional[bool] = None
) -> dict | None :
    """
    Run Azure CLI commands with a spinner, caching, authentication fallback,
    and automatic JSON parsing.

    Defined variables:
        resolved_cmd: List[str]
        expect_json: bool
        full_cmd: List[str]
        full_cmd_str: str
        stdout_or_obj: Union[str, Any]
        stderr: str
        spinner_thread: threading.Thread
        spinner_stop_event: threading.Event
        auth_retry_done: bool

    Defined sub-functions:
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
    """
    # --- State variables ---
    resolved_cmd: List[str]
    expect_json: bool
    full_cmd: List[str]
    full_cmd_str: str
    stdout_or_obj: Union[str, Any]
    stderr: str
    spinner_thread: threading.Thread
    spinner_stop_event: threading.Event
    auth_retry_done: bool = False

    # --- Sub-functions ---

    def _nuke(reason: str, code: int = 99) -> None:
        """
        Log a fatal error and exit the process after showing a countdown spinner.
        """
        logger.error("[run_az] ❌ %s", reason)
        logger.error("[run_az] 💡 Try restarting your terminal or IDE to reload PATH.")
        logger.error("[run_az] ☢️  Nuking program in 10 seconds…")
        spinner = itertools.cycle("|/-\\")
        for i in range(20):
            sys.stdout.write(f"\r[run_az] {next(spinner)} {10 - i // 2}s remaining… ")
            sys.stdout.flush()
            time.sleep(0.5)
        print()
        logger.error("[run_az] 💥 Boom.")
        sys.exit(code)

    def _ensure_azure_cli() -> None:
        """
        Verify that the Azure CLI ('az') dependency is installed. Only runs once.
        """
        from util import milesutil as mu  # noqa: ignore unused import if not used
        if getattr(EnsuredCLI, "ensured_azure_cli", False):
            return
        try:
            mu.Dependency.ensure("milesazure")
            EnsuredCLI.ensured_cli = True
        except Exception as ex:
            _nuke(f"Azure CLI not detected: {ex}", code=98)

    def _resolve_command_path(original: List[str]) -> List[str]:
        """
        Resolve the actual path to the 'az' executable using CMD.which.
        If found, replace original[0]; otherwise return a copy.
        """
        resolved = CMD.which(original[0])
        if resolved:
            return [resolved] + original[1:]
        return original.copy()

    def _should_expect_json(cmd_list: List[str], cap_flag: bool) -> bool:
        """
        Determine whether to append '--output json' based on command and capture_output,
        or honor json_override when provided.
        """
        if json_override is not None:
            return json_override

        joined = " ".join(cmd_list).lower()
        if not cap_flag:
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
            sys.stdout.write(f"\r[run_az] {next(spin)} Running Azure CLI…")
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

    def _execute_with_spinner(
        cmd_list: List[str],
        cap_flag: bool,
        expect_flag: bool
    ) -> Union[tuple[str, str], tuple[Any, str]]:
        """
        Execute the command via Runner.run(..., expect_json=expect_flag) while showing a spinner.
        Return (raw_stdout, stderr) if expect_flag is False,
        or (parsed_obj, "") if expect_flag is True.
        """
        nonlocal spinner_thread, spinner_stop_event

        spinner_stop_event = threading.Event()
        spinner_thread = threading.Thread(
            target=_start_spinner, args=(spinner_stop_event,), daemon=True
        )
        spinner_thread.start()

        try:
            # Use Runner.run to handle shell quoting, JSON parsing, logging, etc.
            result_or_obj = Runner.run(
                cmd_list,
                shell=False,
                capture_output=cap_flag,
                check=True,
                text=True,
                env=None,
                force_global_shell=False,
                cwd=None,
                expect_json=expect_flag
            )
            if expect_flag:
                # If JSON expected, result_or_obj is already a Python object
                return result_or_obj, ""
            else:
                # Otherwise, result_or_obj is CompletedProcess
                completed: subprocess.CompletedProcess = result_or_obj  # type: ignore
                return completed.stdout or "", completed.stderr or ""
        except Exception:
            # Stop spinner before re-raising
            _stop_spinner(spinner_stop_event, spinner_thread)
            raise
        finally:
            # Always attempt to stop the spinner
            try:
                _stop_spinner(spinner_stop_event, spinner_thread)
            except Exception:
                pass

    def _process_success(raw_stdout: str, expect_flag: bool) -> dict:
        """
        Process subprocess output on success. Parse JSON if expected.
        If stdout is empty or not valid JSON, print raw stdout and return {}.
        """
        if not raw_stdout.strip():
            logger.warning("[run_az] ⚠️ Azure CLI returned empty stdout.")
            return {}

        if expect_flag:
            try:
                return json.loads(raw_stdout.strip())
            except json.JSONDecodeError as jde:
                logger.warning("[run_az] ⚠️ Expected JSON but got invalid output: %s", jde)
                print("[run_az] 🔍 Raw stdout:\n" + raw_stdout.strip())
                return {}

        return {}

    def _auth_fallback() -> None:
        """
        Attempt to re-authenticate via Service Principal or device-code flow
        when 'Status_AccountUnusable' is detected.
        """
        nonlocal auth_retry_done
        if auth_retry_done:
            _nuke("[run_az] ⚠️ Authentication retry already attempted.", code=95)
        auth_retry_done = True

        # 1) Logout
        Runner.run(
            ["az", "logout"],
            shell=True,
            capture_output=False,
            check=True,
            text=True,
            force_global_shell=True,
            cwd=None,
            expect_json=False
        )

        # 2) Clear any existing Azure CLI context
        logger.warning("[run_az][AuthFallback] Clearing existing Azure CLI login state…")
        try:
            Runner.run(
                ["az", "account", "clear"],
                shell=True,
                capture_output=False,
                check=True,
                text=True,
                force_global_shell=True,
                cwd=None,
                expect_json=False
            )
        except Exception as e:
            logger.warning("[run_az][AuthFallback] 'az account clear' failed: %s", e)

        # 3) Stop spinner if running
        try:
            spinner_stop_event.set()
            spinner_thread.join()
        except Exception:
            pass

        # 4) Interactive device-code login
        logger.warning("[run_az][AuthFallback] Starting 'az login --use-device-code'…")
        try:
            subprocess.run(
                ["az", "login", "--use-device-code"],
                shell=True,
                check=True,
                text=True
            )
        except Exception as e:
            _nuke(f"[run_az][AuthFallback] 'az login --use-device-code' failed: {e}", code=96)

        # 5) Fetch account details
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

        logger.info("[run_az][AuthFallback] Caching subscription=%s tenant=%s", sub_id, tenant)

        # 6) Warm up Graph token (optional)
        logger.warning("[run_az][AuthFallback] Warming up Graph token…")
        try:
            Runner.run(
                ["az", "account", "get-access-token", "--scope", "https://graph.microsoft.com/.default"],
                shell=True,
                capture_output=False,
                check=True,
                text=True,
                force_global_shell=True,
                cwd=None,
                expect_json=False
            )
        except Exception as e:
            logger.warning("[run_az][AuthFallback] 'get-access-token' failed: %s", e)

    def _handle_subprocess_error(
        stderr_text: str,
        returncode: int,
        cmd_list: List[str]
    ) -> dict:
        """
        Handle errors by checking for built-in auth fallback, user-defined fallbacks,
        ignore rules, or otherwise nuke.
        """
        lower_err = stderr_text.lower()

        # 1) Built-in auth fallback on "accountunusable"
        if "status_accountunusable" in lower_err or "accountunusable" in lower_err:
            logger.warning("[run_az] ⚠️ Detected 'Status_AccountUnusable'. Invoking auth fallback…")
            try:
                _auth_fallback()
                logger.info("[run_az] 🔁 Retrying original command: %s", " ".join(cmd_list))
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
                    logger.warning("[run_az] ⚠️ Triggering fallback handler for '%s'", key)
                    try:
                        handler()
                        logger.info("[run_az] 🔁 Retrying original command: %s", " ".join(cmd_list))
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
                        logger.info(
                            "[run_az] ℹ️ Ignoring '%s' error for '%s'. Continuing.",
                            substr, key
                        )
                        return {}

        if returncode == 1:
            _auth_fallback()

        if returncode == 3:
            return {}

        # If we reach here, no fallback or ignore matched
        _nuke(f"[run_az] Unhandled error (returncode={returncode}): {stderr_text.strip()}", code=99)

    def _normalize_cmd_to_key(cmd: List[str]) -> str:
        clean = []
        for part in cmd:
            part = part.strip('"').strip("'")
            if part.lower().endswith("az.cmd"):
                clean.append("az")
            elif part.startswith("--"):
                clean.append(part.lstrip("-").replace("-", "_"))
            else:
                clean.append(part.replace("-", "_"))
        return ".".join(clean)

    def _check_cached_runs(full_cmd_list: List[str], force_flag: bool) -> Optional[dict]:
        """
        Check whether the command has already been run before, using a normalized dot-separated key.
        """
        key = _normalize_cmd_to_key(full_cmd_list)

        if force_flag:
            logger.debug("[run_az] Force refresh enabled; skipping cache for key '%s'", key)
            return {}

        cache = cache_dict.get(key)
        if key in cache:
            logger.debug("[run_az] Cache hit for key: '%s'", key)
            return cache[key]

        logger.debug("[run_az] Cache miss for key: '%s'", key)
        return None

    # --- Main logic begins here ---

    _ensure_azure_cli()

    # Resolve path to 'az'
    resolved_cmd = _resolve_command_path(cmd)
    logger.info("[run_az] ▶ Running: %s", " ".join(resolved_cmd))

    # Decide if JSON is expected
    expect_json = _should_expect_json(resolved_cmd, capture_output)
    full_cmd = resolved_cmd + (["--output", "json"] if expect_json else [])
    full_cmd_str = " ".join(full_cmd)

    # Check cache
    cached = _check_cached_runs(full_cmd, force_refresh)
    if cached is not None:
        logger.info("[run_az] 💾 Using cached output for: %s", full_cmd_str)
        return cached

    # Execute with spinner + JSON parsing
    try:
        raw_or_obj, stderr = _execute_with_spinner(full_cmd, capture_output, expect_json)

        if expect_json:
            # raw_or_obj is already parsed JSON
            result = raw_or_obj  # type: ignore
        else:
            # raw_or_obj is raw stdout string
            result = _process_success(raw_or_obj, False)

        cmd_key = _normalize_cmd_to_key(full_cmd)

        if isinstance(result, dict):
            cache_dict.set(cmd_key, result)
        else:
            logger.debug("[run_az] Skipped caching non-dict result for: %s (type=%s)", cmd_key, type(result).__name__)

        return result

    except subprocess.CalledProcessError as ex:
        return _handle_subprocess_error(ex.stderr or "", ex.returncode, full_cmd)


CLI_CMDS = {
    # Prerequisites
    "create_resource_group": [
        "az", "group", "create",
        "--name", "{rg_name}",
        "--location", "{location}"
    ],
    "register_kv_provider": [
        "az", "provider", "register",
        "-n", "Microsoft.KeyVault"
    ],

    # Key Vault creation and deletion
    "create_vault": [
        "az", "keyvault", "create",
        "--name", "{vault_name}",
        "--resource-group", "{rg_name}",
        "--location", "{location}"
    ],
    "delete_vault": [
        "az", "keyvault", "delete",
        "--name", "{vault_name}"
    ],

    # HSM‐backed vault variations
    "create_hsm_vault": [
        "az", "keyvault", "create",
        "--name", "{vault_name}",
        "--resource-group", "{rg_name}",
        "--location", "{location}",
        "--sku", "Premium"
    ],

    # Keys
    "create_key": [
        "az", "keyvault", "key", "create",
        "--vault-name", "{vault_name}",
        "--name", "{key_name}",
        "--protection", "{protection}"            # e.g. "software" or "hsm"
    ],
    "import_key": [
        "az", "keyvault", "key", "import",
        "--vault-name", "{vault_name}",
        "--name", "{key_name}",
        "--pem-file", "{pem_path}",
        "--pem-password", "{pem_password}",
        "--protection", "{protection}"            # e.g. "software" or "hsm"
    ],
    "create_hsm_key": [
        "az", "keyvault", "key", "create",
        "--vault-name", "{vault_name}",
        "--name", "{key_name}",
        "--protection", "hsm"
    ],
    "import_hsm_key": [
        "az", "keyvault", "key", "import",
        "--vault-name", "{vault_name}",
        "--name", "{key_name}",
        "--pem-file", "{pem_path}",
        "--protection", "hsm",
        "--pem-password", "{pem_password}"
    ],
    "import_byok": [
        "az", "keyvault", "key", "import",
        "--vault-name", "{vault_name}",
        "--name", "{key_name}",
        "--byok-file", "{byok_path}",
        "--protection", "hsm"
    ],
    "list_keys": [
        "az", "keyvault", "key", "list",
        "--vault-name", "{vault_name}"
    ],
    "show_key": [
        "az", "keyvault", "key", "show",
        "--vault-name", "{vault_name}",
        "--name", "{key_name}"
    ],
    "delete_key": [
        "az", "keyvault", "key", "delete",
        "--vault-name", "{vault_name}",
        "--name", "{key_name}"
    ],

    # Secrets
    "set_secret": [
        "az", "keyvault", "secret", "set",
        "--vault-name", "{vault_name}",
        "--name", "{secret_name}",
        "--value", "{secret_value}"
    ],
    "list_secrets": [
        "az", "keyvault", "secret", "list",
        "--vault-name", "{vault_name}"
    ],
    "show_secret": [
        "az", "keyvault", "secret", "show",
        "--vault-name", "{vault_name}",
        "--name", "{secret_name}"
    ],
    "delete_secret": [
        "az", "keyvault", "secret", "delete",
        "--vault-name", "{vault_name}",
        "--name", "{secret_name}"
    ],

    # Certificates
    "import_cert": [
        "az", "keyvault", "certificate", "import",
        "--vault-name", "{vault_name}",
        "--file", "{cert_path}",
        "--name", "{cert_name}",
        "--password", "{cert_password}"
    ],
    "list_certs": [
        "az", "keyvault", "certificate", "list",
        "--vault-name", "{vault_name}"
    ],
    "show_cert": [
        "az", "keyvault", "certificate", "show",
        "--vault-name", "{vault_name}",
        "--name", "{cert_name}"
    ],
    "delete_cert": [
        "az", "keyvault", "certificate", "delete",
        "--vault-name", "{vault_name}",
        "--name", "{cert_name}"
    ],

    # Access policies
    "set_policy_key": [
        "az", "keyvault", "set-policy",
        "--name", "{vault_name}",
        "--spn", "{spn}",
        "--key-permissions", "{key_permissions}"      # comma-separated list, e.g. "get,decrypt,sign"
    ],
    "set_policy_secret": [
        "az", "keyvault", "set-policy",
        "--name", "{vault_name}",
        "--spn", "{spn}",
        "--secret-permissions", "{secret_permissions}" # comma-separated list, e.g. "get,list"
    ],

    # Advanced vault settings
    "update_vault_deployment": [
        "az", "keyvault", "update",
        "--name", "{vault_name}",
        "--resource-group", "{rg_name}",
        "--enabled-for-deployment", "{true_or_false}"
    ],
    "update_vault_disk": [
        "az", "keyvault", "update",
        "--name", "{vault_name}",
        "--resource-group", "{rg_name}",
        "--enabled-for-disk-encryption", "{true_or_false}"
    ],
    "update_vault_template": [
        "az", "keyvault", "update",
        "--name", "{vault_name}",
        "--resource-group", "{rg_name}",
        "--enabled-for-template-deployment", "{true_or_false}"
    ],

    # Cleanup
    "delete_rg": [
        "az", "group", "delete",
        "--name", "{rg_name}",
        "--yes"
    ],
# App Management
    "app_show": [
        "az", "ad", "app", "show",
        "--id", "{app_id}"
    ],
    "app_create": [
        "az", "ad", "app", "create",
        "--display-name", "{display_name}"
    ],
    "app_delete": [
        "az", "ad", "app", "delete",
        "--id", "{app_id}"
    ],

    # App Credentials
    "app_cred_list": [
        "az", "ad", "app", "credential", "list",
        "--id", "{app_id}"
    ],
    "app_cred_delete": [
        "az", "ad", "app", "credential", "delete",
        "--id", "{app_id}",
        "--key-id", "{key_id}"
    ],
    "app_cred_reset": [
        "az", "ad", "app", "credential", "reset",
        "--id", "{app_id}",
        "--append"
    ],

    # OAuth2 Grants
    "app_permission_list_grants": [
        "az", "ad", "app", "permission", "list-grants",
        "--id", "{app_id}"
    ]
}

def run_az_template(
    cmd_key: str,
    *,
    capture_output: bool = True,
    ignore_errors: Optional[Dict[str, List[str]]] = None,
    fallbacks: Optional[Dict[str, Callable[[], None]]] = None,
    force_refresh: bool = False,
    json_override: Optional[bool] = None,
    **format_kwargs: Any
) -> dict:
    """
    Look up a command template by key in CLI_CMDS, render it with format_kwargs,
    and execute via run_az(...).

    Args:
        cmd_key (str): Key into CLI_CMDS (e.g., "create_vault", "set_secret", etc.).
        capture_output (bool): Forwarded to run_az(...). Defaults to True.
        ignore_errors (Optional[Dict[str, List[str]]]): Forwarded to run_az(...).
        fallbacks (Optional[Dict[str, Callable[[], None]]]): Forwarded to run_az(...).
        force_refresh (bool): Forwarded to run_az(...).
        json_override (Optional[bool]): Forwarded to run_az(...).
        **format_kwargs: Placeholder values for the chosen template.

    Returns:
        dict: Parsed JSON output from run_az (or {} on no‐JSON).

    Raises:
        KeyError: If cmd_key not in CLI_CMDS or a placeholder is missing.
        ValueError: If rendered command still contains '{' or '}'.
        RuntimeError: If run_az(...) itself fails.
    """
    # 1) Validate cmd_key
    if cmd_key not in CLI_CMDS:
        raise KeyError(f"run_az_template: unknown command key '{cmd_key}'")

    template = CLI_CMDS[cmd_key]

    # 2) Render each segment
    rendered: List[str] = []
    for part in template:
        try:
            rendered_part = part.format(**format_kwargs)
        except KeyError as e:
            missing = e.args[0]
            raise KeyError(f"run_az_template: missing placeholder '{missing}' for '{cmd_key}'") from None
        rendered.append(rendered_part)

    # 3) Ensure no unreplaced braces remain
    for segment in rendered:
        if "{" in segment or "}" in segment:
            raise ValueError(f"run_az_template: unreplaced placeholder in segment '{segment}' for '{cmd_key}'")

    # 4) Call run_az(...) with all forwarded options
    try:
        return run_az(
            rendered,
            capture_output=capture_output,
            ignore_errors=ignore_errors,
            fallbacks=fallbacks,
            force_refresh=force_refresh,
            json_override=json_override
        )
    except Exception as e:
        cmd_str = " ".join(rendered)
        raise RuntimeError(f"run_az_template: run_az failed for '{cmd_str}': {e}") from e

# Assume CLI_CMDS and run_az_template are already defined/imported above.

def create_resource_group(
    rg_name: str,
    location: str,
    *,
    capture_output: bool = True,
    ignore_errors: Optional[Dict[str, List[str]]] = None,
    fallbacks: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
    json_override: Optional[bool] = None
) -> dict:
    """
    Create a new Azure resource group by invoking run_az_template with the
    'create_resource_group' template.

    :param rg_name: Name of the resource group to create.
    :param location: Azure region for the resource group.
    :param capture_output: Forwarded to run_az(...). Default True.
    :param ignore_errors: Forwarded to run_az(...). Default None.
    :param fallbacks: Forwarded to run_az(...). Default None.
    :param force_refresh: Forwarded to run_az(...). Default False.
    :param json_override: Forwarded to run_az(...). Default None.
    :return: Parsed JSON result or {} if no JSON output.
    """
    logger.info("Invoking create_resource_group: rg_name=%s, location=%s", rg_name, location)
    return run_az_template(
        "create_resource_group",
        rg_name=rg_name,
        location=location,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh,
        json_override=json_override
    )


def register_kv_provider(
    *,
    capture_output: bool = True,
    ignore_errors: Optional[Dict[str, List[str]]] = None,
    fallbacks: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
    json_override: Optional[bool] = None
) -> dict:
    """
    Register the Microsoft.KeyVault provider in the current subscription
    by invoking run_az_template with the 'register_kv_provider' template.

    :param capture_output: Forwarded to run_az(...). Default True.
    :param ignore_errors: Forwarded to run_az(...). Default None.
    :param fallbacks: Forwarded to run_az(...). Default None.
    :param force_refresh: Forwarded to run_az(...). Default False.
    :param json_override: Forwarded to run_az(...). Default None.
    :return: Parsed JSON result or {} if no JSON output.
    """
    logger.info("Invoking register_kv_provider")
    return run_az_template(
        "register_kv_provider",
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh,
        json_override=json_override
    )


def create_vault(
    vault_name: str,
    rg_name: str,
    location: str,
    *,
    capture_output: bool = True,
    ignore_errors: Optional[Dict[str, List[str]]] = None,
    fallbacks: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
    json_override: Optional[bool] = None
) -> dict:
    """
    Create a new Azure Key Vault by invoking run_az_template with the
    'create_vault' template.

    :param vault_name: Name of the Key Vault to create.
    :param rg_name: Resource group in which to create the vault.
    :param location: Azure region for the vault.
    :param capture_output: Forwarded to run_az(...). Default True.
    :param ignore_errors: Forwarded to run_az(...). Default None.
    :param fallbacks: Forwarded to run_az(...). Default None.
    :param force_refresh: Forwarded to run_az(...). Default False.
    :param json_override: Forwarded to run_az(...). Default None.
    :return: Parsed JSON result or {} if no JSON output.
    """
    logger.info(
        "Invoking create_vault: vault_name=%s, rg_name=%s, location=%s",
        vault_name,
        rg_name,
        location
    )
    return run_az_template(
        "create_vault",
        vault_name=vault_name,
        rg_name=rg_name,
        location=location,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh,
        json_override=json_override
    )


def delete_vault(
    vault_name: str,
    *,
    capture_output: bool = True,
    ignore_errors: Optional[Dict[str, List[str]]] = None,
    fallbacks: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
    json_override: Optional[bool] = None
) -> dict:
    """
    Delete an existing Azure Key Vault by invoking run_az_template with the
    'delete_vault' template.

    :param vault_name: Name of the Key Vault to delete.
    :param capture_output: Forwarded to run_az(...). Default True.
    :param ignore_errors: Forwarded to run_az(...). Default None.
    :param fallbacks: Forwarded to run_az(...). Default None.
    :param force_refresh: Forwarded to run_az(...). Default False.
    :param json_override: Forwarded to run_az(...). Default None.
    :return: Parsed JSON result or {} if no JSON output.
    """
    logger.info("Invoking delete_vault: vault_name=%s", vault_name)
    return run_az_template(
        "delete_vault",
        vault_name=vault_name,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh,
        json_override=json_override
    )


def create_hsm_vault(
    vault_name: str,
    rg_name: str,
    location: str,
    *,
    capture_output: bool = True,
    ignore_errors: Optional[Dict[str, List[str]]] = None,
    fallbacks: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
    json_override: Optional[bool] = None
) -> dict:
    """
    Create a new HSM-backed Azure Key Vault by invoking run_az_template with the
    'create_hsm_vault' template.

    :param vault_name: Name of the HSM-backed Key Vault to create.
    :param rg_name: Resource group in which to create the vault.
    :param location: Azure region for the vault.
    :param capture_output: Forwarded to run_az(...). Default True.
    :param ignore_errors: Forwarded to run_az(...). Default None.
    :param fallbacks: Forwarded to run_az(...). Default None.
    :param force_refresh: Forwarded to run_az(...). Default False.
    :param json_override: Forwarded to run_az(...). Default None.
    :return: Parsed JSON result or {} if no JSON output.
    """
    logger.info(
        "Invoking create_hsm_vault: vault_name=%s, rg_name=%s, location=%s",
        vault_name,
        rg_name,
        location
    )
    return run_az_template(
        "create_hsm_vault",
        vault_name=vault_name,
        rg_name=rg_name,
        location=location,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh,
        json_override=json_override
    )


def create_key(
    vault_name: str,
    key_name: str,
    protection: str,
    *,
    capture_output: bool = True,
    ignore_errors: Optional[Dict[str, List[str]]] = None,
    fallbacks: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
    json_override: Optional[bool] = None
) -> dict:
    """
    Create a new key in an Azure Key Vault by invoking run_az_template with the
    'create_key' template.

    :param vault_name: Name of the Key Vault.
    :param key_name: Name of the key to create.
    :param protection: Protection type ("software" or "hsm").
    :param capture_output: Forwarded to run_az(...). Default True.
    :param ignore_errors: Forwarded to run_az(...). Default None.
    :param fallbacks: Forwarded to run_az(...). Default None.
    :param force_refresh: Forwarded to run_az(...). Default False.
    :param json_override: Forwarded to run_az(...). Default None.
    :return: Parsed JSON result or {} if no JSON output.
    """
    logger.info(
        "Invoking create_key: vault_name=%s, key_name=%s, protection=%s",
        vault_name,
        key_name,
        protection
    )
    return run_az_template(
        "create_key",
        vault_name=vault_name,
        key_name=key_name,
        protection=protection,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh,
        json_override=json_override
    )

def import_key(
    vault_name: str,
    key_name: str,
    pem_path: str,
    pem_password: str,
    protection: str,
    *,
    capture_output: bool = True,
    ignore_errors: Optional[Dict[str, List[str]]] = None,
    fallbacks: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
    json_override: Optional[bool] = None
) -> dict:
    """
    Import an existing key into an Azure Key Vault by invoking run_az_template with
    the 'import_key' template.

    :param vault_name: Name of the Key Vault.
    :param key_name: Name of the key to import.
    :param pem_path: Filesystem path to the .pem file.
    :param pem_password: Password protecting the .pem file.
    :param protection: Protection type ("software" or "hsm").
    :param capture_output: Forwarded to run_az(...). Default True.
    :param ignore_errors: Forwarded to run_az(...). Default None.
    :param fallbacks: Forwarded to run_az(...). Default None.
    :param force_refresh: Forwarded to run_az(...). Default False.
    :param json_override: Forwarded to run_az(...). Default None.
    :return: Parsed JSON result or {} if no JSON output.
    """
    logger.info(
        "Invoking import_key: vault_name=%s, key_name=%s, pem_path=%s, protection=%s",
        vault_name,
        key_name,
        pem_path,
        protection
    )
    return run_az_template(
        "import_key",
        vault_name=vault_name,
        key_name=key_name,
        pem_path=pem_path,
        pem_password=pem_password,
        protection=protection,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh,
        json_override=json_override
    )


def create_hsm_key(
    vault_name: str,
    key_name: str,
    *,
    capture_output: bool = True,
    ignore_errors: Optional[Dict[str, List[str]]] = None,
    fallbacks: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
    json_override: Optional[bool] = None
) -> dict:
    """
    Create a new HSM-protected key in an Azure Key Vault by invoking run_az_template
    with the 'create_hsm_key' template.

    :param vault_name: Name of the Key Vault.
    :param key_name: Name of the key to create.
    :param capture_output: Forwarded to run_az(...). Default True.
    :param ignore_errors: Forwarded to run_az(...). Default None.
    :param fallbacks: Forwarded to run_az(...). Default None.
    :param force_refresh: Forwarded to run_az(...). Default False.
    :param json_override: Forwarded to run_az(...). Default None.
    :return: Parsed JSON result or {} if no JSON output.
    """
    logger.info("Invoking create_hsm_key: vault_name=%s, key_name=%s", vault_name, key_name)
    return run_az_template(
        "create_hsm_key",
        vault_name=vault_name,
        key_name=key_name,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh,
        json_override=json_override
    )


def import_hsm_key(
    vault_name: str,
    key_name: str,
    pem_path: str,
    pem_password: str,
    *,
    capture_output: bool = True,
    ignore_errors: Optional[Dict[str, List[str]]] = None,
    fallbacks: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
    json_override: Optional[bool] = None
) -> dict:
    """
    Import an HSM-protected key into an Azure Key Vault by invoking run_az_template
    with the 'import_hsm_key' template.

    :param vault_name: Name of the Key Vault.
    :param key_name: Name of the key to import.
    :param pem_path: Filesystem path to the .pem file.
    :param pem_password: Password protecting the .pem file.
    :param capture_output: Forwarded to run_az(...). Default True.
    :param ignore_errors: Forwarded to run_az(...). Default None.
    :param fallbacks: Forwarded to run_az(...). Default None.
    :param force_refresh: Forwarded to run_az(...). Default False.
    :param json_override: Forwarded to run_az(...). Default None.
    :return: Parsed JSON result or {} if no JSON output.
    """
    logger.info(
        "Invoking import_hsm_key: vault_name=%s, key_name=%s, pem_path=%s",
        vault_name,
        key_name,
        pem_path
    )
    return run_az_template(
        "import_hsm_key",
        vault_name=vault_name,
        key_name=key_name,
        pem_path=pem_path,
        pem_password=pem_password,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh,
        json_override=json_override
    )


def import_byok(
    vault_name: str,
    key_name: str,
    byok_path: str,
    *,
    capture_output: bool = True,
    ignore_errors: Optional[Dict[str, List[str]]] = None,
    fallbacks: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
    json_override: Optional[bool] = None
) -> dict:
    """
    Import a BYOK (Bring Your Own Key) into an Azure Key Vault by invoking
    run_az_template with the 'import_byok' template.

    :param vault_name: Name of the Key Vault.
    :param key_name: Name of the key to import.
    :param byok_path: Filesystem path to the BYOK file.
    :param capture_output: Forwarded to run_az(...). Default True.
    :param ignore_errors: Forwarded to run_az(...). Default None.
    :param fallbacks: Forwarded to run_az(...). Default None.
    :param force_refresh: Forwarded to run_az(...). Default False.
    :param json_override: Forwarded to run_az(...). Default None.
    :return: Parsed JSON result or {} if no JSON output.
    """
    logger.info(
        "Invoking import_byok: vault_name=%s, key_name=%s, byok_path=%s",
        vault_name,
        key_name,
        byok_path
    )
    return run_az_template(
        "import_byok",
        vault_name=vault_name,
        key_name=key_name,
        byok_path=byok_path,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh,
        json_override=json_override
    )


def list_keys(
    vault_name: str,
    *,
    capture_output: bool = True,
    ignore_errors: Optional[Dict[str, List[str]]] = None,
    fallbacks: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
    json_override: Optional[bool] = None
) -> dict:
    """
    List all keys in an Azure Key Vault by invoking run_az_template with
    the 'list_keys' template.

    :param vault_name: Name of the Key Vault.
    :param capture_output: Forwarded to run_az(...). Default True.
    :param ignore_errors: Forwarded to run_az(...). Default None.
    :param fallbacks: Forwarded to run_az(...). Default None.
    :param force_refresh: Forwarded to run_az(...). Default False.
    :param json_override: Forwarded to run_az(...). Default None.
    :return: Parsed JSON result or {} if no JSON output.
    """
    logger.info("Invoking list_keys: vault_name=%s", vault_name)
    return run_az_template(
        "list_keys",
        vault_name=vault_name,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh,
        json_override=json_override
    )


def show_key(
    vault_name: str,
    key_name: str,
    *,
    capture_output: bool = True,
    ignore_errors: Optional[Dict[str, List[str]]] = None,
    fallbacks: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
    json_override: Optional[bool] = None
) -> dict:
    """
    Show details of a specific key in an Azure Key Vault by invoking
    run_az_template with the 'show_key' template.

    :param vault_name: Name of the Key Vault.
    :param key_name: Name of the key to show.
    :param capture_output: Forwarded to run_az(...). Default True.
    :param ignore_errors: Forwarded to run_az(...). Default None.
    :param fallbacks: Forwarded to run_az(...). Default None.
    :param force_refresh: Forwarded to run_az(...). Default False.
    :param json_override: Forwarded to run_az(...). Default None.
    :return: Parsed JSON result or {} if no JSON output.
    """
    logger.info("Invoking show_key: vault_name=%s, key_name=%s", vault_name, key_name)
    return run_az_template(
        "show_key",
        vault_name=vault_name,
        key_name=key_name,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh,
        json_override=json_override
    )


def delete_key(
    vault_name: str,
    key_name: str,
    *,
    capture_output: bool = True,
    ignore_errors: Optional[Dict[str, List[str]]] = None,
    fallbacks: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
    json_override: Optional[bool] = None
) -> dict:
    """
    Delete a specific key from an Azure Key Vault by invoking run_az_template
    with the 'delete_key' template.

    :param vault_name: Name of the Key Vault.
    :param key_name: Name of the key to delete.
    :param capture_output: Forwarded to run_az(...). Default True.
    :param ignore_errors: Forwarded to run_az(...). Default None.
    :param fallbacks: Forwarded to run_az(...). Default None.
    :param force_refresh: Forwarded to run_az(...). Default False.
    :param json_override: Forwarded to run_az(...). Default None.
    :return: Parsed JSON result or {} if no JSON output.
    """
    logger.info("Invoking delete_key: vault_name=%s, key_name=%s", vault_name, key_name)
    return run_az_template(
        "delete_key",
        vault_name=vault_name,
        key_name=key_name,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh,
        json_override=json_override
    )


def set_secret(
    vault_name: str,
    secret_name: str,
    secret_value: str,
    *,
    capture_output: bool = True,
    ignore_errors: Optional[Dict[str, List[str]]] = None,
    fallbacks: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
    json_override: Optional[bool] = None
) -> dict:
    """
    Set a secret in an Azure Key Vault by invoking run_az_template with the
    'set_secret' template.

    :param vault_name: Name of the Key Vault.
    :param secret_name: Name of the secret to set.
    :param secret_value: Value of the secret.
    :param capture_output: Forwarded to run_az(...). Default True.
    :param ignore_errors: Forwarded to run_az(...). Default None.
    :param fallbacks: Forwarded to run_az(...). Default None.
    :param force_refresh: Forwarded to run_az(...). Default False.
    :param json_override: Forwarded to run_az(...). Default None.
    :return: Parsed JSON result or {} if no JSON output.
    """
    logger.info(
        "Invoking set_secret: vault_name=%s, secret_name=%s",
        vault_name,
        secret_name
    )
    return run_az_template(
        "set_secret",
        vault_name=vault_name,
        secret_name=secret_name,
        secret_value=secret_value,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh,
        json_override=json_override
    )


def list_secrets(
    vault_name: str,
    *,
    capture_output: bool = True,
    ignore_errors: Optional[Dict[str, List[str]]] = None,
    fallbacks: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
    json_override: Optional[bool] = None
) -> dict:
    """
    List all secrets in an Azure Key Vault by invoking run_az_template with
    the 'list_secrets' template.

    :param vault_name: Name of the Key Vault.
    :param capture_output: Forwarded to run_az(...). Default True.
    :param ignore_errors: Forwarded to run_az(...). Default None.
    :param fallbacks: Forwarded to run_az(...). Default None.
    :param force_refresh: Forwarded to run_az(...). Default False.
    :param json_override: Forwarded to run_az(...). Default None.
    :return: Parsed JSON result or {} if no JSON output.
    """
    logger.info("Invoking list_secrets: vault_name=%s", vault_name)
    return run_az_template(
        "list_secrets",
        vault_name=vault_name,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh,
        json_override=json_override
    )


def show_secret(
    vault_name: str,
    secret_name: str,
    *,
    capture_output: bool = True,
    ignore_errors: Optional[Dict[str, List[str]]] = None,
    fallbacks: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
    json_override: Optional[bool] = None
) -> dict:
    """
    Show a specific secret in an Azure Key Vault by invoking run_az_template with
    the 'show_secret' template.

    :param vault_name: Name of the Key Vault.
    :param secret_name: Name of the secret to retrieve.
    :param capture_output: Forwarded to run_az(...). Default True.
    :param ignore_errors: Forwarded to run_az(...). Default None.
    :param fallbacks: Forwarded to run_az(...). Default None.
    :param force_refresh: Forwarded to run_az(...). Default False.
    :param json_override: Forwarded to run_az(...). Default None.
    :return: Parsed JSON result or {} if no JSON output.
    """
    logger.info("Invoking show_secret: vault_name=%s, secret_name=%s", vault_name, secret_name)
    return run_az_template(
        "show_secret",
        vault_name=vault_name,
        secret_name=secret_name,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh,
        json_override=json_override
    )


def delete_secret(
    vault_name: str,
    secret_name: str,
    *,
    capture_output: bool = True,
    ignore_errors: Optional[Dict[str, List[str]]] = None,
    fallbacks: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
    json_override: Optional[bool] = None
) -> dict:
    """
    Delete a specific secret from an Azure Key Vault by invoking run_az_template
    with the 'delete_secret' template.

    :param vault_name: Name of the Key Vault.
    :param secret_name: Name of the secret to delete.
    :param capture_output: Forwarded to run_az(...). Default True.
    :param ignore_errors: Forwarded to run_az(...). Default None.
    :param fallbacks: Forwarded to run_az(...). Default None.
    :param force_refresh: Forwarded to run_az(...). Default False.
    :param json_override: Forwarded to run_az(...). Default None.
    :return: Parsed JSON result or {} if no JSON output.
    """
    logger.info("Invoking delete_secret: vault_name=%s, secret_name=%s", vault_name, secret_name)
    return run_az_template(
        "delete_secret",
        vault_name=vault_name,
        secret_name=secret_name,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh,
        json_override=json_override
    )


def import_cert(
    vault_name: str,
    cert_path: str,
    cert_name: str,
    cert_password: str,
    *,
    capture_output: bool = True,
    ignore_errors: Optional[Dict[str, List[str]]] = None,
    fallbacks: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
    json_override: Optional[bool] = None
) -> dict:
    """
    Import a certificate into an Azure Key Vault by invoking run_az_template with
    the 'import_cert' template.

    :param vault_name: Name of the Key Vault.
    :param cert_path: Filesystem path to the certificate file.
    :param cert_name: Name under which to store the certificate in the vault.
    :param cert_password: Password protecting the certificate file.
    :param capture_output: Forwarded to run_az(...). Default True.
    :param ignore_errors: Forwarded to run_az(...). Default None.
    :param fallbacks: Forwarded to run_az(...). Default None.
    :param force_refresh: Forwarded to run_az(...). Default False.
    :param json_override: Forwarded to run_az(...). Default None.
    :return: Parsed JSON result or {} if no JSON output.
    """
    logger.info(
        "Invoking import_cert: vault_name=%s, cert_path=%s, cert_name=%s",
        vault_name,
        cert_path,
        cert_name
    )
    return run_az_template(
        "import_cert",
        vault_name=vault_name,
        cert_path=cert_path,
        cert_name=cert_name,
        cert_password=cert_password,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh,
        json_override=json_override
    )


def list_certs(
    vault_name: str,
    *,
    capture_output: bool = True,
    ignore_errors: Optional[Dict[str, List[str]]] = None,
    fallbacks: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
    json_override: Optional[bool] = None
) -> dict:
    """
    List all certificates in an Azure Key Vault by invoking run_az_template with
    the 'list_certs' template.

    :param vault_name: Name of the Key Vault.
    :param capture_output: Forwarded to run_az(...). Default True.
    :param ignore_errors: Forwarded to run_az(...). Default None.
    :param fallbacks: Forwarded to run_az(...). Default None.
    :param force_refresh: Forwarded to run_az(...). Default False.
    :param json_override: Forwarded to run_az(...). Default None.
    :return: Parsed JSON result or {} if no JSON output.
    """
    logger.info("Invoking list_certs: vault_name=%s", vault_name)
    return run_az_template(
        "list_certs",
        vault_name=vault_name,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh,
        json_override=json_override
    )


def show_cert(
    vault_name: str,
    cert_name: str,
    *,
    capture_output: bool = True,
    ignore_errors: Optional[Dict[str, List[str]]] = None,
    fallbacks: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
    json_override: Optional[bool] = None
) -> dict:
    """
    Show a specific certificate in an Azure Key Vault by invoking run_az_template with
    the 'show_cert' template.

    :param vault_name: Name of the Key Vault.
    :param cert_name: Name of the certificate to retrieve.
    :param capture_output: Forwarded to run_az(...). Default True.
    :param ignore_errors: Forwarded to run_az(...). Default None.
    :param fallbacks: Forwarded to run_az(...). Default None.
    :param force_refresh: Forwarded to run_az(...). Default False.
    :param json_override: Forwarded to run_az(...). Default None.
    :return: Parsed JSON result or {} if no JSON output.
    """
    logger.info("Invoking show_cert: vault_name=%s, cert_name=%s", vault_name, cert_name)
    return run_az_template(
        "show_cert",
        vault_name=vault_name,
        cert_name=cert_name,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh,
        json_override=json_override
    )


def delete_cert(
    vault_name: str,
    cert_name: str,
    *,
    capture_output: bool = True,
    ignore_errors: Optional[Dict[str, List[str]]] = None,
    fallbacks: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
    json_override: Optional[bool] = None
) -> dict:
    """
    Delete a specific certificate from an Azure Key Vault by invoking run_az_template
    with the 'delete_cert' template.

    :param vault_name: Name of the Key Vault.
    :param cert_name: Name of the certificate to delete.
    :param capture_output: Forwarded to run_az(...). Default True.
    :param ignore_errors: Forwarded to run_az(...). Default None.
    :param fallbacks: Forwarded to run_az(...). Default None.
    :param force_refresh: Forwarded to run_az(...). Default False.
    :param json_override: Forwarded to run_az(...). Default None.
    :return: Parsed JSON result or {} if no JSON output.
    """
    logger.info("Invoking delete_cert: vault_name=%s, cert_name=%s", vault_name, cert_name)
    return run_az_template(
        "delete_cert",
        vault_name=vault_name,
        cert_name=cert_name,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh,
        json_override=json_override
    )


def set_policy_key(
    vault_name: str,
    spn: str,
    key_permissions: str,
    *,
    capture_output: bool = True,
    ignore_errors: Optional[Dict[str, List[str]]] = None,
    fallbacks: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
    json_override: Optional[bool] = None
) -> dict:
    """
    Assign key permissions to a service principal for a Key Vault by invoking
    run_az_template with the 'set_policy_key' template.

    :param vault_name: Name of the Key Vault.
    :param spn: Service principal object ID or application ID.
    :param key_permissions: Comma-separated list of key permissions
                            (e.g., "get,decrypt,sign").
    :param capture_output: Forwarded to run_az(...). Default True.
    :param ignore_errors: Forwarded to run_az(...). Default None.
    :param fallbacks: Forwarded to run_az(...). Default None.
    :param force_refresh: Forwarded to run_az(...). Default False.
    :param json_override: Forwarded to run_az(...). Default None.
    :return: Parsed JSON result or {} if no JSON output.
    """
    logger.info(
        "Invoking set_policy_key: vault_name=%s, spn=%s, key_permissions=%s",
        vault_name,
        spn,
        key_permissions
    )
    return run_az_template(
        "set_policy_key",
        vault_name=vault_name,
        spn=spn,
        key_permissions=key_permissions,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh,
        json_override=json_override
    )


def set_policy_secret(
    vault_name: str,
    spn: str,
    secret_permissions: str,
    *,
    capture_output: bool = True,
    ignore_errors: Optional[Dict[str, List[str]]] = None,
    fallbacks: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
    json_override: Optional[bool] = None
) -> dict:
    """
    Assign secret permissions to a service principal for a Key Vault by invoking
    run_az_template with the 'set_policy_secret' template.

    :param vault_name: Name of the Key Vault.
    :param spn: Service principal object ID or application ID.
    :param secret_permissions: Comma-separated list of secret permissions
                               (e.g., "get,list").
    :param capture_output: Forwarded to run_az(...). Default True.
    :param ignore_errors: Forwarded to run_az(...). Default None.
    :param fallbacks: Forwarded to run_az(...). Default None.
    :param force_refresh: Forwarded to run_az(...). Default False.
    :param json_override: Forwarded to run_az(...). Default None.
    :return: Parsed JSON result or {} if no JSON output.
    """
    logger.info(
        "Invoking set_policy_secret: vault_name=%s, spn=%s, secret_permissions=%s",
        vault_name,
        spn,
        secret_permissions
    )
    return run_az_template(
        "set_policy_secret",
        vault_name=vault_name,
        spn=spn,
        secret_permissions=secret_permissions,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh,
        json_override=json_override
    )


def update_vault_deployment(
    vault_name: str,
    rg_name: str,
    true_or_false: str,
    *,
    capture_output: bool = True,
    ignore_errors: Optional[Dict[str, List[str]]] = None,
    fallbacks: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
    json_override: Optional[bool] = None
) -> dict:
    """
    Enable or disable 'enabled-for-deployment' on a Key Vault by invoking
    run_az_template with the 'update_vault_deployment' template.

    :param vault_name: Name of the Key Vault.
    :param rg_name: Resource group of the Key Vault.
    :param true_or_false: "true" or "false".
    :param capture_output: Forwarded to run_az(...). Default True.
    :param ignore_errors: Forwarded to run_az(...). Default None.
    :param fallbacks: Forwarded to run_az(...). Default None.
    :param force_refresh: Forwarded to run_az(...). Default False.
    :param json_override: Forwarded to run_az(...). Default None.
    :return: Parsed JSON result or {} if no JSON output.
    """
    logger.info(
        "Invoking update_vault_deployment: vault_name=%s, rg_name=%s, enabled=%s",
        vault_name,
        rg_name,
        true_or_false
    )
    return run_az_template(
        "update_vault_deployment",
        vault_name=vault_name,
        rg_name=rg_name,
        true_or_false=true_or_false,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh,
        json_override=json_override
    )


def update_vault_disk(
    vault_name: str,
    rg_name: str,
    true_or_false: str,
    *,
    capture_output: bool = True,
    ignore_errors: Optional[Dict[str, List[str]]] = None,
    fallbacks: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
    json_override: Optional[bool] = None
) -> dict:
    """
    Enable or disable 'enabled-for-disk-encryption' on a Key Vault by invoking
    run_az_template with the 'update_vault_disk' template.

    :param vault_name: Name of the Key Vault.
    :param rg_name: Resource group of the Key Vault.
    :param true_or_false: "true" or "false".
    :param capture_output: Forwarded to run_az(...). Default True.
    :param ignore_errors: Forwarded to run_az(...). Default None.
    :param fallbacks: Forwarded to run_az(...). Default None.
    :param force_refresh: Forwarded to run_az(...). Default False.
    :param json_override: Forwarded to run_az(...). Default None.
    :return: Parsed JSON result or {} if no JSON output.
    """
    logger.info(
        "Invoking update_vault_disk: vault_name=%s, rg_name=%s, enabled=%s",
        vault_name,
        rg_name,
        true_or_false
    )
    return run_az_template(
        "update_vault_disk",
        vault_name=vault_name,
        rg_name=rg_name,
        true_or_false=true_or_false,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh,
        json_override=json_override
    )


def update_vault_template(
    vault_name: str,
    rg_name: str,
    true_or_false: str,
    *,
    capture_output: bool = True,
    ignore_errors: Optional[Dict[str, List[str]]] = None,
    fallbacks: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
    json_override: Optional[bool] = None
) -> dict:
    """
    Enable or disable 'enabled-for-template-deployment' on a Key Vault by invoking
    run_az_template with the 'update_vault_template' template.

    :param vault_name: Name of the Key Vault.
    :param rg_name: Resource group of the Key Vault.
    :param true_or_false: "true" or "false".
    :param capture_output: Forwarded to run_az(...). Default True.
    :param ignore_errors: Forwarded to run_az(...). Default None.
    :param fallbacks: Forwarded to run_az(...). Default None.
    :param force_refresh: Forwarded to run_az(...). Default False.
    :param json_override: Forwarded to run_az(...). Default None.
    :return: Parsed JSON result or {} if no JSON output.
    """
    logger.info(
        "Invoking update_vault_template: vault_name=%s, rg_name=%s, enabled=%s",
        vault_name,
        rg_name,
        true_or_false
    )
    return run_az_template(
        "update_vault_template",
        vault_name=vault_name,
        rg_name=rg_name,
        true_or_false=true_or_false,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh,
        json_override=json_override
    )


def delete_rg(
    rg_name: str,
    *,
    capture_output: bool = True,
    ignore_errors: Optional[Dict[str, List[str]]] = None,
    fallbacks: Optional[Dict[str, Any]] = None,
    force_refresh: bool = False,
    json_override: Optional[bool] = None
) -> dict:
    """
    Delete an Azure resource group by invoking run_az_template with the
    'delete_rg' template.

    :param rg_name: Name of the resource group to delete.
    :param capture_output: Forwarded to run_az(...). Default True.
    :param ignore_errors: Forwarded to run_az(...). Default None.
    :param fallbacks: Forwarded to run_az(...). Default None.
    :param force_refresh: Forwarded to run_az(...). Default False.
    :param json_override: Forwarded to run_az(...). Default None.
    :return: Parsed JSON result or {} if no JSON output.
    """
    logger.info("Invoking delete_rg: rg_name=%s", rg_name)
    return run_az_template(
        "delete_rg",
        rg_name=rg_name,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh,
        json_override=json_override
    )

def app_show(
    app_id: str,
    *,
    capture_output: bool = True,
    ignore_errors: Optional[Dict[str, List[str]]] = None,
    fallbacks: Optional[Dict[str, Callable[[], None]]] = None,
    force_refresh: bool = False,
    json_override: Optional[bool] = None
) -> dict:
    """
    Get the details of an Azure AD application.

    :param app_id: The object ID or appId of the application to show.
    :param capture_output: Forwarded to run_az(...). Default True.
    :param ignore_errors: Forwarded to run_az(...). Default None.
    :param fallbacks: Forwarded to run_az(...). Default None.
    :param force_refresh: Forwarded to run_az(...). Default False.
    :param json_override: Forwarded to run_az(...). Default None.
    :return: Parsed JSON result of 'az ad app show'.
    """
    logger.info("Invoking app_show: app_id=%s", app_id)
    return run_az_template(
        "app_show",
        app_id=app_id,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh,
        json_override=json_override
    )


def app_create(
    display_name: str,
    *,
    capture_output: bool = True,
    ignore_errors: Optional[Dict[str, List[str]]] = None,
    fallbacks: Optional[Dict[str, Callable[[], None]]] = None,
    force_refresh: bool = False,
    json_override: Optional[bool] = None
) -> dict:
    """
    Create a new Azure AD application.

    :param display_name: Display name for the new application.
    :param identifier_uris: Comma-separated list of identifier URIs (e.g., "api://myapp").
    :param reply_urls: Comma-separated list of reply URLs (e.g., "https://localhost/signin").
    :param capture_output: Forwarded to run_az(...). Default True.
    :param ignore_errors: Forwarded to run_az(...). Default None.
    :param fallbacks: Forwarded to run_az(...). Default None.
    :param force_refresh: Forwarded to run_az(...). Default False.
    :param json_override: Forwarded to run_az(...). Default None.
    :return: Parsed JSON result of 'az ad app create'.
    """
    logger.info(
        "Invoking app_create: display_name=%s, identifier_uris=%s, reply_urls=%s",
        display_name
    )
    return run_az_template(
        "app_create",
        display_name=display_name,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh,
        json_override=json_override
    )


def app_delete(
    app_id: str,
    *,
    capture_output: bool = True,
    ignore_errors: Optional[Dict[str, List[str]]] = None,
    fallbacks: Optional[Dict[str, Callable[[], None]]] = None,
    force_refresh: bool = False,
    json_override: Optional[bool] = None
) -> dict:
    """
    Delete an existing Azure AD application.

    :param app_id: The object ID or appId of the application to delete.
    :param capture_output: Forwarded to run_az(...). Default True.
    :param ignore_errors: Forwarded to run_az(...). Default None.
    :param fallbacks: Forwarded to run_az(...). Default None.
    :param force_refresh: Forwarded to run_az(...). Default False.
    :param json_override: Forwarded to run_az(...). Default None.
    :return: Parsed JSON result of 'az ad app delete'.
    """
    logger.info("Invoking app_delete: app_id=%s", app_id)
    return run_az_template(
        "app_delete",
        app_id=app_id,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh,
        json_override=json_override
    )


def app_cred_list(
    app_id: str,
    *,
    capture_output: bool = True,
    ignore_errors: Optional[Dict[str, List[str]]] = None,
    fallbacks: Optional[Dict[str, Callable[[], None]]] = None,
    force_refresh: bool = False,
    json_override: Optional[bool] = None
) -> dict:
    """
    List an application's password or certificate credential metadata.

    :param app_id: The object ID or appId of the application to list credentials for.
    :param capture_output: Forwarded to run_az(...). Default True.
    :param ignore_errors: Forwarded to run_az(...). Default None.
    :param fallbacks: Forwarded to run_az(...). Default None.
    :param force_refresh: Forwarded to run_az(...). Default False.
    :param json_override: Forwarded to run_az(...). Default None.
    :return: Parsed JSON result of 'az ad app credential list'.
    """
    logger.info("Invoking app_cred_list: app_id=%s", app_id)
    return run_az_template(
        "app_cred_list",
        app_id=app_id,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh,
        json_override=json_override
    )


def app_cred_delete(
    app_id: str,
    key_id: str,
    *,
    capture_output: bool = True,
    ignore_errors: Optional[Dict[str, List[str]]] = None,
    fallbacks: Optional[Dict[str, Callable[[], None]]] = None,
    force_refresh: bool = False,
    json_override: Optional[bool] = None
) -> dict:
    """
    Delete an application's password or certificate credential.

    :param app_id: The object ID or appId of the application to delete the credential from.
    :param key_id: The keyId (credential ID) to remove.
    :param capture_output: Forwarded to run_az(...). Default True.
    :param ignore_errors: Forwarded to run_az(...). Default None.
    :param fallbacks: Forwarded to run_az(...). Default None.
    :param force_refresh: Forwarded to run_az(...). Default False.
    :param json_override: Forwarded to run_az(...). Default None.
    :return: Parsed JSON result of 'az ad app credential delete'.
    """
    logger.info("Invoking app_cred_delete: app_id=%s, key_id=%s", app_id, key_id)
    return run_az_template(
        "app_cred_delete",
        app_id=app_id,
        key_id=key_id,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh,
        json_override=json_override
    )


def app_cred_reset(
    app_id: str,
    *,
    append: bool = True,
    display_name: Optional[str] = None,
    end_date: Optional[str] = None,
    start_date: Optional[str] = None,
    key_type: Optional[str] = None,
    key_usage: Optional[str] = None,
    years: Optional[int] = None,
    password: Optional[str] = None,
    cert: Optional[str] = None,
    create_cert: Optional[bool] = None,
    subject: Optional[str] = None,
    san: Optional[str] = None,
    capture_output: bool = True,
    ignore_errors: Optional[Dict[str, List[str]]] = None,
    fallbacks: Optional[Dict[str, Callable[[], None]]] = None,
    force_refresh: bool = False,
    json_override: Optional[bool] = None
) -> dict:
    """
    Reset an application's password or certificate credentials.

    :param app_id: The object ID or appId of the application to reset credentials for.
    :param append: If True, append the new credential instead of overwriting. Default True.
    :param display_name: Friendly name for the new credential (optional).
    :param end_date: Expiration date for the new credential (ISO 8601 format, optional).
    :param start_date: Start date for the new credential (ISO 8601 format, optional).
    :param key_type: Type of key: "Password" or "Cert" (optional).
    :param key_usage: Usage of key: "Sign" or "Verify" (optional).
    :param years: Number of years for the new credential to be valid (optional).
    :param password: Manually specify a password (if resetting a secret, optional).
    :param cert: Path to a PEM/PFX certificate (if resetting a cert, optional).
    :param create_cert: If True, generate a new self-signed certificate (optional).
    :param subject: Certificate subject name (if creating a new cert, optional).
    :param san: Subject alternative name (if creating a new cert, optional).
    :param capture_output: Forwarded to run_az(...). Default True.
    :param ignore_errors: Forwarded to run_az(...). Default None.
    :param fallbacks: Forwarded to run_az(...). Default None.
    :param force_refresh: Forwarded to run_az(...). Default False.
    :param json_override: Forwarded to run_az(...). Default None.
    :return: Parsed JSON result of 'az ad app credential reset'.
    """
    logger.info("Invoking app_cred_reset: app_id=%s", app_id)
    return run_az_template(
        "app_cred_reset",
        app_id=app_id,
        append=str(append).lower(),
        display_name=display_name or "",
        end_date=end_date or "",
        start_date=start_date or "",
        key_type=key_type or "",
        key_usage=key_usage or "",
        years=str(years) if years is not None else "",
        password=password or "",
        cert=cert or "",
        create_cert=str(create_cert).lower() if create_cert is not None else "false",
        subject=subject or "",
        san=san or "",
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh,
        json_override=json_override
    )


def app_permission_list_grants(
    app_id: str,
    *,
    capture_output: bool = True,
    ignore_errors: Optional[Dict[str, List[str]]] = None,
    fallbacks: Optional[Dict[str, Callable[[], None]]] = None,
    force_refresh: bool = False,
    json_override: Optional[bool] = None
) -> dict:
    """
    List OAuth2 permission grants for a given Azure AD application.

    :param app_id: The object ID or appId of the application.
    :param capture_output: Forwarded to run_az(...). Default True.
    :param ignore_errors: Forwarded to run_az(...). Default None.
    :param fallbacks: Forwarded to run_az(...). Default None.
    :param force_refresh: Forwarded to run_az(...). Default False.
    :param json_override: Forwarded to run_az(...). Default None.
    :return: Parsed JSON result of 'az ad app permission list-grants'.
    """
    logger.info("Invoking app_permission_list_grants: app_id=%s", app_id)
    return run_az_template(
        "app_permission_list_grants",
        app_id=app_id,
        capture_output=capture_output,
        ignore_errors=ignore_errors,
        fallbacks=fallbacks,
        force_refresh=force_refresh,
        json_override=json_override
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