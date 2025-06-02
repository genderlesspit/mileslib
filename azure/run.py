# run.py

def run_az(
    cmd: list[str],
    *,
    capture_output: bool = True,
    ignore_errors: dict[str, list[str]] | None = None
) -> dict:
    """
    Run 'az ...', parse JSON output, or exit on unexpected failures.
    If you pass `ignore_errors={"someKey": ["substring1", "substring2"]}`,
    then any CalledProcessError whose stderr contains any of those substrings
    (case-insensitive) will be swallowed (return {}), instead of calling _nuke().
    """
    from util import milesutil as mu
    from util.milessubprocess.cmd import CMD
    import sys, json, time, itertools, subprocess

    def _nuke(reason: str, code: int = 99):
        print(f"\n[run_az] ❌ {reason}")
        print("[run_az] 💡 Try restarting your terminal or IDE to reload PATH.")
        print(f"[run_az] ☢️  Nuking program in 10 seconds...")
        spinner = itertools.cycle("|/-\\")
        for i in range(20):
            sys.stdout.write(f"\r[run_az] {next(spinner)} {10 - i//2}s remaining... ")
            sys.stdout.flush()
            time.sleep(0.5)
        print("\n[run_az] 💥 Boom.")
        sys.exit(code)

    # 1) Ensure Azure CLI is present
    try:
        mu.Dependency.ensure("azure")
    except Exception as ex:
        _nuke(f"Azure CLI not detected: {ex}", code=98)

    # 2) Resolve any “az” fallback path
    resolved = CMD.which(cmd[0])
    if resolved:
        cmd[0] = resolved

    print(f"[AzureClient] ▶ Running: {' '.join(cmd)}")

    # 3) Decide if we expect JSON back
    expect_json = (
        capture_output
        and "--use-device-code" not in cmd
        and "login" not in cmd
    )
    full_cmd = cmd + (["--output", "json"] if expect_json else [])

    try:
        completed = mu.run(
            full_cmd,
            capture_output=capture_output,
            text=True,
            check=True,
            shell=False
        )

        if not completed or completed.stdout is None or not completed.stdout.strip():
            if expect_json:
                _nuke("Azure CLI returned no stdout (possibly non-JSON or interactive mode)", code=97)
            else:
                print("[run_az] ✅ Completed interactive command (no JSON expected).")
                return {}

        raw = completed.stdout.strip()
        return json.loads(raw) if expect_json and raw else {}

    except subprocess.CalledProcessError as ex:
        # 4) Inspect stderr and compare against ignore_errors patterns
        stderr = (ex.stderr or "").lower()
        if ignore_errors:
            for key, substrings in ignore_errors.items():
                for substr in substrings:
                    if substr.lower() in stderr:
                        print(f"[run_az] ℹ️ Ignoring '{substr}' error for '{key}'. Continuing.")
                        return {}
        # otherwise—unrecognized error → nuke
        err = stderr or str(ex)
        _nuke(f"Azure CLI failed (code {ex.returncode}): {' '.join(full_cmd)} ↳ {err}", code=96)

    except Exception as ex:
        _nuke(f"Azure CLI command failed: {' '.join(full_cmd)} ↳ {ex}", code=96)
