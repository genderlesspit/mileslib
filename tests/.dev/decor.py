import functools
from typing import Any

class Return:
    @staticmethod
    def return_decorator(expected_return: Any, fuzzy: bool = False) -> Any:
        def decorator(fn):
            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                er = expected_return

                actual_return = fn(*args, **kwargs)
                ar = actual_return

                if fuzzy:
                    if not isinstance(ar, type(er)): raise TypeError(f"[{fn.__name__}] Deviated from expected type!: Expected: {expected_return}; Actual: {actual_return}")

                if actual_return != expected_return: raise ValueError(f"[{fn.__name__}] Deviated from expected result!: Expected: {expected_return}; Actual: {actual_return}")

                return actual_return
            return wrapper
        return decorator

test_return = Return.return_decorator

class Patcher:
    @staticmethod
    def patcher_decorator(expected_return: Any, patch: Any) -> Any:
        def decorator(fn):
            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                decorated = Return.return_decorator(expected_return)(fn)
                try: return decorated(*args, **kwargs)
                except ValueError: return patch
            return wrapper
        return decorator

test_patcher = Patcher.patcher_decorator
