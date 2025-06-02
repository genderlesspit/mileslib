import inspect
import ast
import inspect
import shutil
import subprocess
import textwrap
from functools import wraps
from pathlib import Path
from unittest.mock import MagicMock


class SanityTester:
    """
    SanityTester dynamically validates a function's logic by generating and executing
    runtime tests via Pynguin before allowing the original function to run.

    Primary use case: debugging or development-phase logic validation of functions
    with minimal test coverage or unknown side-effects.

    Workflow Steps:

    Step 1 – AST Scan for Dependencies:
        Parses the target function’s source code using `inspect.getsource()` and `ast.parse()`.
        Extracts all function calls and global references (e.g., `os.getenv`, `CONFIG.get`).

    Step 2 – Determine Mock Targets:
        Walks the AST to identify candidate dependencies for mocking.
        Any symbol not defined in the local function scope is marked as a mock target.
        Result: a list of dotted-path dependencies (e.g., ["os.getenv", "CONFIG.get"]).

    Step 3 – Generate Mocked Module:
        Copies or rewrites the original module to inject mocks.
        Uses `unittest.mock.patch()` to replace identified dependencies with
        stubs or user-defined mocks (via decorator args).

    Step 4 – Run Pynguin on the Mocked Module:
        Launches Pynguin via milessubprocess, pointing to the patched module.
        Pynguin generates unit tests against the function under the mocked context.

    Step 5 – Run Pynguin Tests:
        Executes the generated tests using `pytest`.
        Captures results; if any test fails, logs the error and blocks function execution.

    Step 6 – Execute Real Function:
        Only if all dynamic tests pass, the real function is executed with original inputs.

    Parameters (via decorator):
        - debug (bool): Enable or disable sanity check mode.
        - mocks (dict): Optional dict of {dotted_path: return_value or callable}.
        - expected (Any): Optional expected return value to assert against.
        - timeout (int): Timeout for Pynguin milessubprocess execution.

    Note:
        This class assumes a development/debug context and is not intended for production-critical paths
        without strict control of execution timing and mocking scope.
    """

    # ========================
    # Configurable Constants
    # ========================
    TEMP_DIR = Path(".sanitytemp")      # Directory for mocked modules + Pynguin output
    PYNGUIN_CLI = shutil.which("pynguin") or "pynguin"  # safe fallback

    @staticmethod
    def extract_dependencies(func) -> dict:
        """
        Parses the AST of a function to identify all external dependencies.
        """
        called_funcs: set[str] = set()
        global_names: set[str] = set()

        class Analyzer(ast.NodeVisitor):
            def visit_Call(self, node):
                if isinstance(node.func, ast.Attribute):
                    parts = []
                    current = node.func
                    while isinstance(current, ast.Attribute):
                        parts.insert(0, current.attr)
                        current = current.value
                    if isinstance(current, ast.Name):
                        parts.insert(0, current.id)
                    full_path = ".".join(parts)
                    called_funcs.add(full_path)
                elif isinstance(node.func, ast.Name):
                    called_funcs.add(node.func.id)
                self.generic_visit(node)

            def visit_Name(self, node):
                if isinstance(node.ctx, ast.Load):
                    global_names.add(node.id)
                self.generic_visit(node)

        try:
            source = inspect.getsource(func)
            source = textwrap.dedent(source)  # 🔧 fix here
            tree = ast.parse(source)
            Analyzer().visit(tree)
        except Exception as e:
            raise ValueError(f"Failed to parse function {func.__name__}: {e}")

        return {
            "called_functions": sorted(called_funcs),
            "global_names": sorted(global_names),
        }

    @staticmethod
    def resolve_mock_targets(deps: dict, func: callable) -> list:
        """
        Filters out which symbols from the dependency scan should be mocked.

        This logic compares called/global names against the function’s local scope
        (args, defined functions, local vars) and retains only external symbols
        that need to be patched during testing.

        Args:
            deps (dict): Output of extract_dependencies(). Should contain:
                - "called_functions": list of str
                - "global_names": list of str
            func (callable): The original function to analyze.

        Returns:
            list[str]: List of dotted-path symbols that should be mocked.

        Raises:
            ValueError: If function locals cannot be introspected.
        """

        # 1. Vars
        func_code = func.__code__
        local_vars = set(func_code.co_varnames[:func_code.co_argcount])
        candidate_funcs = set(deps.get("called_functions", []))
        candidate_globals = set(deps.get("global_names", []))
        to_mock = set()

        # 2. Subfunctions
        import builtins

        def is_external(name: str) -> bool:
            """
            Determines if a symbol is external to the function scope and should be mocked.
            """
            base = name.split(".")[0]

            if base in local_vars:
                return False
            if base in func.__globals__:
                return True
            if hasattr(builtins, base):
                return False
            if base in {"staticmethod", "classmethod", "property"}:
                return False
            return True  # fallback for unknowns

        # 3. Logic
        for name in candidate_funcs.union(candidate_globals):
            if is_external(name):
                to_mock.add(name)

        return sorted(to_mock)

    @staticmethod
    def create_mocked_module(original_path: Path, mock_targets: list, mocks: dict = None) -> Path:
        """
        Creates a temporary version of the source module with selected symbols patched via `unittest.mock`.

        This allows Pynguin to analyze the function in an isolated environment with external dependencies
        safely replaced by mocks. User-specified mock return values or callables can be injected.

        Args:
            original_path (Path): Path to the original `.py` source file where the function is defined.
            mock_targets (list): List of dotted-path symbols to patch (e.g., "os.getenv", "CONFIG.get").
            mocks (dict, optional): Mapping of mock_target → mock return_value or callable.
                                    If not provided, all patches use `MagicMock`.

        Returns:
            Path: Path to the temporary module containing the patched code.

        Raises:
            IOError: If the original file cannot be read or the temporary file cannot be written.
        """

        # 1. Vars
        temp_dir = SanityTester.TEMP_DIR
        temp_dir.mkdir(parents=True, exist_ok=True)
        module_name = original_path.stem
        temp_file_path = temp_dir / f"{module_name}_mocked.py"
        patch_lines = []

        # 2. Subfunction
        def make_patch_line(symbol: str) -> str:
            """
            Generates a line of code that patches a given symbol.

            Args:
                symbol (str): Dotted path (e.g., "os.getenv").

            Returns:
                str: Python line of code with patch.
            """
            mock_value = mocks.get(symbol, "MagicMock()") if mocks else "MagicMock()"
            return f"{symbol} = {mock_value}"

        # 3. Logic
        try:
            original_code = original_path.read_text(encoding="utf-8")
        except Exception as e:
            raise IOError(f"Failed to read original source file: {e}")

        # Inject imports + mocks at top of file
        patch_lines.append("from unittest.mock import MagicMock")
        if mocks:
            for val in mocks.values():
                if callable(val):
                    patch_lines.append("from types import FunctionType  # for callable mocks")

        for symbol in mock_targets:
            patch_lines.append(make_patch_line(symbol))

        patched_code = "\n".join(patch_lines) + "\n\n" + original_code

        try:
            temp_file_path.write_text(patched_code, encoding="utf-8")
        except Exception as e:
            raise IOError(f"Failed to write mocked module: {e}")

        return temp_file_path

    @staticmethod
    def run_pynguin(module_path: Path, function_name: str, timeout: int = 10) -> bool:
        """
        Launches Pynguin in milessubprocess mode to generate test cases for the given function.

        Args:
            module_path (Path): Path to the Python module (mocked or original) to analyze.
            function_name (str): Name of the function (no module prefix).
            timeout (int): Max time in seconds to wait for Pynguin to complete.

        Returns:
            bool: True if Pynguin completed successfully and generated tests.
                  False if timed out or failed.

        Raises:
            RuntimeError: If Pynguin crashes or milessubprocess execution fails.
        """

        # 1. Vars
        if not shutil.which(SanityTester.PYNGUIN_CLI):
            raise RuntimeError("Pynguin CLI not found in PATH. Please install it via `pip install pynguin`.")

        module_name = module_path.stem
        test_dir = module_path.parent / "tests"
        test_dir.mkdir(exist_ok=True)
        result: subprocess.CompletedProcess

        # 2. Subfunction
        def build_pynguin_command() -> list:
            """
            Constructs the CLI command to invoke Pynguin with appropriate flags.

            Returns:
                list: CLI command split as a list for milessubprocess.
            """
            return [
                SanityTester.PYNGUIN_CLI,
                "--project-path", str(module_path.parent.resolve()),
                "--module-name", module_name,
                "--output-path", str(test_dir),
                "--coverage-type", "branch",  # optional, but improves test diversity
                "--maximum-search-time", str(timeout),
                "--entrypoint", f"{module_name}.{function_name}",
            ]

        # 3. Logic
        try:
            print(f"[SanityTester] Running Pynguin on {module_name}.{function_name}")
            result = subprocess.run(
                build_pynguin_command(),
                capture_output=True,
                text=True,
                timeout=timeout + 5  # slight buffer
            )
            print(f"[SanityTester] Pynguin stdout:\n{result.stdout}")
            print(f"[SanityTester] Pynguin stderr:\n{result.stderr}")

            return result.returncode == 0
        except subprocess.TimeoutExpired:
            print(f"[SanityTester] Pynguin timed out for {function_name}")
            return False
        except Exception as e:
            raise RuntimeError(f"Failed to run Pynguin: {e}")

    @staticmethod
    def run_generated_tests(test_output_path: Path) -> bool:
        """
        Executes tests generated by Pynguin using pytest.

        Args:
            test_output_path (Path): Path to the test output directory or specific test file.

        Returns:
            bool: True if all tests passed, False if any failed.

        Raises:
            RuntimeError: If pytest execution fails or test output is invalid.
        """

        # 1. Vars
        test_path = test_output_path if test_output_path.is_dir() else test_output_path.parent
        result: subprocess.CompletedProcess

        # 2. Subfunction
        def run_pytest() -> subprocess.CompletedProcess:
            """
            Invokes pytest via milessubprocess with clean output.

            Returns:
                CompletedProcess object containing return code and output.
            """
            return subprocess.run(
                ["pytest", str(test_path), "--maxfail=1", "--disable-warnings", "--quiet"],
                capture_output=True,
                text=True
            )

        # 3. Logic
        try:
            print(f"[SanityTester] Running generated tests in: {test_path}")
            result = run_pytest()
            print(f"[SanityTester] Pytest stdout:\n{result.stdout}")
            print(f"[SanityTester] Pytest stderr:\n{result.stderr}")
            return result.returncode == 0
        except Exception as e:
            raise RuntimeError(f"Test run failed: {e}")

    @staticmethod
    def sanity_wrap(*, mocks=None, expected=None, debug=True, timeout=10):
        """
        Decorator factory for wrapping a function with pre-execution sanity testing.

        Usage:
            @SanityTester.sanity_wrap(mocks=..., expected=..., debug=...)
            def my_func(): ...

        Returns:
            callable: A decorator that wraps the original function.
        """

        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                # Vars
                func_name = func.__name__
                module_path = Path(inspect.getfile(func)).resolve()

                if not debug:
                    return func(*args, **kwargs)

                print(f"[SanityTester] Running sanity test for `{func_name}`")

                try:
                    # Step 1: Extract dependencies
                    deps = SanityTester.extract_dependencies(func)

                    # Step 2: Identify mock targets
                    mock_targets = SanityTester.resolve_mock_targets(deps, func)

                    # Step 3: Generate mocked module
                    mocked_path = SanityTester.create_mocked_module(
                        original_path=module_path,
                        mock_targets=mock_targets,
                        mocks=mocks or {}
                    )

                    # Step 4: Run Pynguin
                    pynguin_success = SanityTester.run_pynguin(mocked_path, func_name, timeout)
                    if not pynguin_success:
                        raise RuntimeError("Pynguin failed to generate valid tests")

                    # Step 5: Run the tests
                    tests_passed = SanityTester.run_generated_tests(mocked_path.parent / "tests")
                    if not tests_passed:
                        raise AssertionError("Sanity test failed — logic regression or unmocked dependency")

                    # Optional return value check
                    if expected is not None:
                        test_result = func(*args, **kwargs)
                        assert test_result == expected, f"Return mismatch: got {test_result}, expected {expected}"
                        return test_result

                    # Step 6: Run real function
                    return func(*args, **kwargs)

                except Exception as e:
                    print(f"[SanityTester] Aborting execution of `{func_name}`: {e}")
                    raise

            return wrapper

        return decorator


class Dummy:
    @staticmethod
    def pure_add(x, y):
        return x + y

    @staticmethod
    def uses_os():
        import os
        return os.getenv("MY_VAR")

    @staticmethod
    def uses_global():
        return CONFIG.get("x")

CONFIG = {"x": 123}

def test_extract_dependencies():
    print("\n[debug] Running test_extract_dependencies")
    deps = SanityTester.extract_dependencies(Dummy.pure_add)
    print(f"[debug] Deps: {deps}")
    assert isinstance(deps, dict)
    assert "called_functions" in deps
    assert "global_names" in deps
    assert "x" in deps["global_names"] or not deps["global_names"]  # depends on implementation

def test_resolve_mock_targets_with_globals():
    print("\n[debug] Running test_resolve_mock_targets_with_globals")
    deps = SanityTester.extract_dependencies(Dummy.uses_global)
    targets = SanityTester.resolve_mock_targets(deps, Dummy.uses_global)
    print(f"[debug] Mock targets: {targets}")
    assert "CONFIG.get" in targets or "CONFIG" in targets

def test_create_mocked_module(tmp_path):
    print("\n[debug] Running test_create_mocked_module")
    dummy_code = """
def my_func():
    import os
    return os.getenv("MY_VAR")
"""
    orig_path = tmp_path / "dummy_module.py"
    orig_path.write_text(dummy_code)

    mock_targets = ["os.getenv"]
    mocks = {"os.getenv": "'mocked_value'"}
    mocked = SanityTester.create_mocked_module(orig_path, mock_targets, mocks)
    print(f"[debug] Mocked module path: {mocked}")
    assert mocked.exists()
    content = mocked.read_text()
    print(f"[debug] Mocked content:\n{content}")
    assert "os.getenv = 'mocked_value'" in content

def test_run_pynguin_fails_cleanly(tmp_path):
    print("\n[debug] Running test_run_pynguin_fails_cleanly")
    # This should fail because the dummy function doesn't exist
    dummy_code = "def fn(): pass"
    dummy_file = tmp_path / "bad_module.py"
    dummy_file.write_text(dummy_code)

    success = SanityTester.run_pynguin(dummy_file, "nonexistent_fn", timeout=2)
    print(f"[debug] Pynguin success: {success}")
    assert success is False

@SanityTester.sanity_wrap(
    mocks={"os.getenv": "'DEV_MODE'"},
    expected="DEV_MODE",
    debug=True,
    timeout=5
)
def get_mode_from_env():
    import os
    return os.getenv("APP_MODE")

def test_get_mode_from_env_sanity_check(monkeypatch):
    print("\n[debug] Running test_get_mode_from_env_sanity_check")

    # Ensure function runs without error and passes sanity test
    monkeypatch.setenv("APP_MODE", "DEV_MODE")
    result = get_mode_from_env()
    print(f"[debug] Result: {result}")
    assert result == "DEV_MODE"
