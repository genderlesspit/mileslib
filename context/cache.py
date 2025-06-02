# cache.py

import threading
from typing import Callable, Optional, Union

from context.config import cfg
from context.envloader import EnvLoader
from util import milesutil as mu  # for mu.recall

class Cache:
    """
    General‐purpose cache that layers:
      1. In‐memory (fast)
      2. .env via EnvLoader (persistent)

    Designed for namespacing (e.g. per‐project). All values are stored as strings.
    The `recall` parameter can be used to supply a fallback value or function
    if a key is not found in memory/.env:
      - If `recall` is a string, it is treated as a default value.
      - If `recall` is a Callable, it is invoked (via mu.recall) to produce and store a value.
    """

    # { namespace (str) : { key (str) : value (str) } }
    _store: dict[str, dict[str, str]] = {}
    _temp_store: dict[str, dict[str, str]] = {}
    _lock = threading.Lock()

    @staticmethod
    def get(
        namespace: str,
        key: str,
        recall: Union[str, Callable[[], str], None] = None
    ) -> Optional[str]:
        """
        Lookup process:
          1. Check in‐memory cache under [namespace][key].
          2. If missing, attempt EnvLoader.get(f"{namespace}.{key}", required=False).
             • If found, write it back into in‐memory and return.
          3. If still missing:
             a) If recall is a string → store that string to memory + .env, return it.
             b) If recall is a callable → invoke via mu.recall() to get a value,
                store that to memory + .env, return it.
             c) Otherwise, return None.

        Args:
            namespace (str): Top‐level grouping (e.g. project name).
            key       (str): Specific key under that namespace.
            recall    (str|Callable|None):
                       • If str: used as default value when missing.
                       • If Callable: called (via mu.recall) to generate/fix the value.

        Returns:
            Optional[str]: The found or recalled string, or None if not found and no recall.
        """
        with Cache._lock:
            if namespace not in Cache._store:
                Cache._store[namespace] = {}
            ns_dict = Cache._store[namespace]

            # 1. In‐memory lookup
            if key in ns_dict:
                print(f"[Cache] (M) {namespace}.{key} = {ns_dict[key]}")
                return ns_dict[key]

        # 2. Fallback to .env
        try:
            val = EnvLoader.get(f"{namespace}.{key}", required=False)
        except Exception:
            val = None

        if val is not None:
            with Cache._lock:
                Cache._store[namespace][key] = val
            print(f"[Cache] (E) {namespace}.{key} = {val}")
            return val

        # 3. Not found in memory or .env → handle recall if provided
        if isinstance(recall, str):
            with Cache._lock:
                Cache._store[namespace][key] = recall
            EnvLoader.write(f"{namespace}.{key}", recall, replace_existing=True)
            print(f"[Cache] (R-string) {namespace}.{key} = {recall}")
            return recall

        if callable(recall):
            try:
                print(f"[Cache.get] Attempting recall: {recall.__name__}")
                result = recall()  # ✅ one-time call
            except Exception as e:
                raise RuntimeError(f"[Cache.get] recall function '{recall.__name__}' failed: {e}")

            if not isinstance(result, str):
                print(f"[Cache.get] ⚠️ recall returned type={type(result)} value={result!r}")
                raise TypeError(f"[Cache.get] recall returned non-str: {result!r}")

            with Cache._lock:
                Cache._store[namespace][key] = result
            EnvLoader.write(f"{namespace}.{key}", result)
            print(f"[Cache] (R-callable) {namespace}.{key} = {result}")
            return result

        # 4. Neither found nor recalled → MISS
        print(f"[Cache] MISS {namespace}.{key}")
        return None

    @staticmethod
    def set(
        namespace: str,
        key: str,
        value: str,
        include_in_cfg: Optional[str] = None
    ) -> None:
        """
        Store into in‐memory and persist to .env as "{namespace}.{key}".

        Args:
            namespace       (str)
            key             (str)
            value           (str): Value to store.
            include_in_cfg  (str|None): If provided, write to config under that project.
        """
        if not isinstance(namespace, str) or not isinstance(key, str):
            raise TypeError("Cache.set: namespace and key must be strings")
        if not isinstance(value, str):
            raise TypeError("Cache.set: value must be a string")

        with Cache._lock:
            if namespace not in Cache._store:
                Cache._store[namespace] = {}
            Cache._store[namespace][key] = value

        EnvLoader.write(f"{namespace}.{key}", value)
        print(f"[Cache] SET {namespace}.{key} = {value}")

        if include_in_cfg:
            project = include_in_cfg
            mu.check_types(project, str)

            # Defensive fix: resolve config path safely
            project_path = EnvLoader.get(f"{project}.config_path")
            if isinstance(project_path, str):
                from pathlib import Path
                project_path = Path(project_path)

            cfg.write(project_path, set={namespace: {key: value}})


    @staticmethod
    def exists(namespace: str, key: str) -> bool:
        """
        Returns True if in‐memory or .env has a non‐None value for this key.

        Args:
            namespace (str)
            key       (str)

        Returns:
            bool
        """
        with Cache._lock:
            if namespace in Cache._store and key in Cache._store[namespace]:
                print(f"[Cache] EXISTS (M) {namespace}.{key}")
                return True

        try:
            val = EnvLoader.get(f"{namespace}.{key}", required=False)
            if val is not None:
                with Cache._lock:
                    if namespace not in Cache._store:
                        Cache._store[namespace] = {}
                    Cache._store[namespace][key] = val
                print(f"[Cache] EXISTS (E) {namespace}.{key}")
                return True
        except Exception:
            pass

        print(f"[Cache] NOT_EXISTS {namespace}.{key}")
        return False

    @staticmethod
    def clear(namespace: str, key: Optional[str] = None) -> None:
        """
        Clear either:
          • a specific key under this namespace, or
          • the entire namespace if key is None.

        Does NOT delete from .env. To remove from .env, call:
          EnvLoader.write(f"{namespace}.{key}", delete=True)

        Args:
            namespace (str)
            key       (Optional[str])
        """
        with Cache._lock:
            if namespace not in Cache._store:
                return

            if key is None:
                Cache._store.pop(namespace, None)
                print(f"[Cache] CLEARED namespace '{namespace}'")
            else:
                Cache._store[namespace].pop(key, None)
                print(f"[Cache] CLEARED {namespace}.{key}")

    @staticmethod
    def temp_set(namespace: str, key: str, value: str) -> None:
        """
        Store a temporary, in‐memory‐only value. Does NOT persist to .env.

        Args:
            namespace (str)
            key       (str)
            value     (str)
        """
        if not isinstance(namespace, str) or not isinstance(key, str):
            raise TypeError("Cache.temp_set: namespace and key must be strings")
        if not isinstance(value, str):
            raise TypeError("Cache.temp_set: value must be a string")

        with Cache._lock:
            if namespace not in Cache._temp_store:
                Cache._temp_store[namespace] = {}
            Cache._temp_store[namespace][key] = value

        print(f"[Cache] TEMP SET {namespace}.{key} = {value}")

    @staticmethod
    def temp_get(namespace: str, key: str) -> Optional[str]:
        """
        Retrieve a temporary, in‐memory‐only value. Returns None if not set.

        Args:
            namespace (str)
            key       (str)

        Returns:
            Optional[str]
        """
        with Cache._lock:
            if namespace in Cache._temp_store and key in Cache._temp_store[namespace]:
                val = Cache._temp_store[namespace][key]
                print(f"[Cache] TEMP GET {namespace}.{key} = {val}")
                return val

        print(f"[Cache] TEMP MISS {namespace}.{key}")
        return None
