import json
import sys
import time
import threading
import itertools
import subprocess
import logging
from typing import Callable, Optional

logger = logging.getLogger(__name__)


def run_az(
    cmd: list[str],
    *,
    capture_output: bool = True,
    ignore_errors: dict[str, list[str]] | None = None,
    fallbacks: dict[str, Callable[[], None]] | None = None
) -> dict:
    """
    Run Azure CLI commands with a spinner and default Python logging.

    All defined variables:
        resolved_cmd: list[str]
        expect_json: bool
        full_cmd: list[str]
        proc: subprocess.Popen
        stdout: str
        stderr: str

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

    Logic:
        1. Ensure Azure CLI dependency is present.
        2. Resolve path to 'az' executable.
        3. Determine if JSON output is expected.
        4. Build the final command (adding '--output json' if needed).
        5. Start a spinner thread.
        6. Execute the subprocess and wait, showing spinner.
        7. On success, parse JSON or return {}.
        8. On failure, attempt fallbacks, ignore rules, or exit.
    """

    # Defined variables
    resolved_cmd: list[str]
    expect_json: bool
    full_cmd: list[str]
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
        print()  # newline after spinner
        logger.error("[run_az] 💥 Boom.")
        sys.exit(code)

    def _ensure_azure_cli() -> None:
        """
        Verify that the Azure CLI ('milesazure') dependency is installed.
        """
        from util import milesutil as mu

        try:
            mu.Dependency.ensure("milesazure")
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
        if "--use-device-code" in joined:
            return False
        if " login" in joined or "account set" in joined:
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
        # Clear spinner line once stopped
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

        # Prepare the subprocess
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

        # Start spinner thread
        spinner_stop_event = threading.Event()
        spinner_thread = threading.Thread(target=_start_spinner, args=(spinner_stop_event,), daemon=True)
        spinner_thread.start()

        # Wait for process to finish
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

        # 1) Fallback handling
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
                            fallbacks=fallbacks
                        )
                    except Exception as fallback_ex:
                        _nuke(f"Fallback for '{key}' failed: {fallback_ex}", code=95)

        # 2) Ignore specific error substrings
        if ignore_errors:
            for key, substrings in ignore_errors.items():
                for substr in substrings:
                    if substr.lower() in lower_err:
                        logger.info(f"[run_az] ℹ️ Ignoring '{substr}' error for '{key}'. Continuing.")
                        return {}

        # 3) Final nuke
        _nuke(f"Azure CLI failed (code {returncode}): {' '.join(cmd_list)} ↳ {lower_err}", code=96)

    # Logic begins here

    # 1) Ensure Azure CLI is present
    _ensure_azure_cli()

    # 2) Resolve 'az' path
    resolved_cmd = _resolve_command_path(cmd)

    # 3) Log command starting
    logger.info(f"[run_az] ▶ Running: {' '.join(resolved_cmd)}")

    # 4) Decide if JSON expected
    expect_json = _should_expect_json(resolved_cmd, capture_output)

    # 5) Build final command list
    full_cmd = resolved_cmd + (["--output", "json"] if expect_json else [])

    # 6) Execute and capture output with spinner
    try:
        stdout, stderr = _execute_with_spinner(full_cmd, capture_output)
        _stop_spinner(spinner_stop_event, spinner_thread)
        return _process_success(stdout, expect_json)
    except subprocess.CalledProcessError as ex:
        _stop_spinner(spinner_stop_event, spinner_thread)
        return _handle_subprocess_error(ex.stderr or "", ex.returncode, full_cmd)
