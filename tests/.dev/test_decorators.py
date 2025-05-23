def mileslib(
    *,
    retry=False,
    retries=3,
    fix=None,
    backoff_base=None,
    timed=False,
    logged=False,
    safe=False,
    env=False,       # <- NEW
    label=None
):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            name = label or fn.__name__

            if env:
                print(f"[{name}] Loading environment variables...")
                StaticMethods.EnvLoader.load_env()  # Cache into os.environ/_cache

            def core():
                if logged:
                    print(f"[{name}] Calling with args={args}, kwargs={kwargs}")
                if timed:
                    start = time.time()
                result = fn(*args, **kwargs)
                if timed:
                    print(f"[{name}] Completed in {time.time() - start:.3f}s")
                return result

            if retry:
                return StaticMethods.ErrorHandling.attempt(
                    lambda: core(),
                    retries=retries,
                    fix=fix,
                    backoff_base=backoff_base,
                    label=name
                )
            elif safe:
                try:
                    return core()
                except Exception as e:
                    print(f"[{name}] Caught exception: {e}")
                    return None
            else:
                return core()

        return wrapper
    return decorator
