import time
from typing import Callable, Union, List, Any, Optional, Type, Tuple

class ErrorHandling:
    @staticmethod
    def recall(fn: Callable, fix: Union[Callable, List[Callable]]) -> Any:
        """
        Calls a zero-argument function with retry logic and one or more fix strategies.

        If `fn()` fails, will try one or more `fix()` strategies to recover and reattempt.

        Args:
            fn (Callable[[], Any]): Primary function to run.
            fix (Callable or list of Callable): Fix strategy or list of fallback functions.

        Returns:
            Any: Result of the successful call to `fn`.

        Raises:
            RuntimeError: If all fix attempts fail.
            TypeError: If non-callables are passed.
        """
        if not callable(fn):
            raise TypeError("[recall] First argument must be callable")

        # Try the main function first
        try:
            result = fn()
            print(f"[recall] Primary function succeeded")
            return result
        except Exception as e:
            print(f"[recall] Primary function failed: {e}")

        # Try fix(es)
        fixes = fix if isinstance(fix, list) else [fix]
        for i, fix_fn in enumerate(fixes):
            if not callable(fix_fn):
                raise TypeError(f"[recall] Fix at index {i} is not callable: {fix_fn}")
            try:
                print(f"[recall] Attempting fix #{i + 1}: {fix_fn.__name__}")
                fix_fn()
                print(f"[recall] Fix #{i + 1} succeeded. Retrying primary function...")
                result = fn()
                print(f"[recall] Retry succeeded after fix #{i + 1}")
                return result
            except Exception as fix_err:
                print(f"[recall] Fix #{i + 1} failed: {fix_err}")

        raise RuntimeError("[recall] All fix strategies failed. Aborting.")

    @staticmethod
    def attempt(
            fn: Callable,
            retries: int = 3,
            fix: Optional[Callable[[], None]] = None,
            backoff_base: Optional[int] = None,
            label: str = "operation",
    ) -> Any:
        """
        Executes a no-argument callable with retry logic, optional fix handler, and timing.

        This function expects that `fn` and `fix` are zero-argument callables.
        If your function requires parameters, wrap it in a `lambda` or use `functools.partial`.

        Args:
            fn (Callable[[], Any]): A zero-argument callable to execute (e.g., lambda: my_func(x)).
            retries (int): Number of retry attempts (default: 3).
            fix (Callable[[], None], optional): One-time recovery callable to run after the first failure.
            backoff_base (int, optional): If set, applies exponential backoff (e.g., 2 = 1s, 2s, 4s).
            label (str): Label for logging and timing context.

        Returns:
            Any: The result of `fn()` if successful.

        Raises:
            RuntimeError: If `fix()` fails or is reused.
            Exception: The last raised exception if all retries fail.
        """
        label = label or getattr(fn, "__name__", "operation")
        last_exception = None
        attempted_fix = False

        for current_attempt in range(1, retries + 1):
            try:
                result = fn()
                print(f"[{label}] Success on attempt {current_attempt}")
                return result
            except Exception as e:
                if attempted_fix is True: raise RuntimeError
                last_exception = e
                print(f"[{label}] Attempt {current_attempt}/{retries} failed: {e}")
                if fix:
                    try:
                        print(f"[{label}] Attempting to fix using {fix}...")
                        fix()
                        attempted_fix = True
                        continue
                    except:
                        print(f"[{label}] Fix failed!")
                        raise RuntimeError
                if current_attempt < retries and backoff_base:
                    delay = backoff_base ** (current_attempt - 1)
                    print(f"[{label}] Retrying in {delay}s...")
                    time.sleep(delay)
                    continue
                print(f"[{label}] All {retries} attempts failed.")

        raise last_exception

    @staticmethod
    def check_types(arg: Any, expected: Union[Type, Tuple[Type, ...], list], label: str = "check_types") -> Any:
        """
        Verifies that the input or each item in a list matches any of the expected type(s).
        Raises TypeError if any do not match.

        Args:
            arg (Any): The argument or list of arguments to check.
            expected (Type, tuple, or list of types): Acceptable types (e.g., str, int).
            label (str): Label for clearer error messages.

        Returns:
            The original arg if valid.

        Raises:
            TypeError: If any input does not match the expected types.
        """

        # Normalize expected types to tuple
        if isinstance(expected, list):
            expected_types = tuple(expected)
        elif isinstance(expected, type):
            expected_types = (expected,)
        elif isinstance(expected, tuple):
            expected_types = expected
        else:
            raise TypeError(f"[{label}] Invalid 'expected' type: {type(expected)}")

        def _validate(x):
            if not isinstance(x, expected_types):
                type_names = ", ".join(t.__name__ for t in expected_types)
                raise TypeError(f"[{label}] Expected type(s): {type_names}; got {type(x).__name__}")

        if isinstance(arg, list):
            for i, item in enumerate(arg):
                _validate(item)
        else:
            _validate(arg)

        return arg

attempt = ErrorHandling.attempt
recall = ErrorHandling.recall
check_input = ErrorHandling.check_types
check_types = ErrorHandling.check_types
ERROR_USAGE = """
    StaticMethods ErrorHandling Aliases
    -----------------------------------

    These utility functions are exposed via aliases for convenience:

    timer(label="operation") -> Callable
        CLIDecorator to time and log the execution duration of a function.
        Example:
            @timer("process_data")
            def process_data(): ...

    attempt(fn, *args, retries=3, backoff_base=None, handled_exceptions=(Exception,), label="operation", **kwargs) -> Any
        Execute a function with retry logic, automatic timing, and logging.
        Retries on specified exceptions and supports exponential backoff.

    recall(fn, *args, **kwargs) -> Any
        Alias for `attempt`. Useful when semantically retrying previous logic.

    check_input(arg, expected, label="Input") -> None
        Assert that an argument matches the expected type(s). Raises TypeError if not.
        Example:
            check_input(user_id, int, label="user_id")

    try_import(package_name: str) -> Module
        Attempts to import a package by name. If missing, installs via pip and retries.
        Raises RuntimeError on failure.
        Example:
            loguru = try_import("loguru")
"""