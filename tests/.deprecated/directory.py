class Directory:
    """
    Handles root directory validation, configuration setup, and global project state.

    Attributes:
        setup_complete (bool): Indicates whether initialization has completed.
        absolute_path (Path): The validated root directory of the MilesLib project.
    """
    setup_complete = False
    absolute_path = None

    def __init__(self, root: Path = None):
        """
        Initialize the Directory object and set up the core configuration structure.

        Args:
            root (Path, optional): Custom root path. Defaults to current working directory.

        Raises:
            ValueError: If the directory or config file cannot be created or validated.
        """
        self.root = sm.validate_directory((root or os.getcwd()).resolve())
        Directory.absolute_path = self.root
        self.config_name = "mileslib_config.toml"
        self.config_dir = sm.validate_directory(self.root / "_config")
        config_path = self.config_dir / self.config_name

        try:
            self.config_path = sm.validate_file(config_path)
        except FileNotFoundError:
            print("[debug] Config file not found, writing new one...")
            try:
                sm.cfg_write(
                    pdir=self.root,
                    file_name=self.config_name,
                    data={
                        "valid": True,
                        "absolute_root": str(self.root),
                    },
                    section="mileslib",
                    overwrite=False,
                    replace_existing=False
                )
            except Exception as e:
                raise RuntimeError(f"[cfg_write error] {e}")

            # Now confirm it's there
            if not config_path.exists():
                raise RuntimeError(f"Config still missing after write: {config_path}")
            self.config_path = sm.validate_file(config_path)
        except IsADirectoryError:
            raise RuntimeError("Config file is actually a directory...?")

        Directory.setup_complete = True

    @mileslib(label="Directory.validate", retry=True, safe=False)
    @staticmethod
    def validate():
        """
        Ensure the MilesLib project root is properly initialized and accessible.

        This method follows a multi-step validation flow:
          1. If `Directory.absolute_path` is already set, return it immediately.
          2. Otherwise, attempt to load the project root from the local config file at `_config/mileslib_config.toml`.
          3. If the config is missing or malformed, automatically invoke `mileslib setup` via milessubprocess.
          4. After setup, retry loading the configuration to finalize initialization.

        Returns:
            Path: The absolute path of the MilesLib project root.

        Raises:
            RuntimeError: If initialization fails due to missing config, setup failure, or unreadable config state.
        """
        def _load_from_config() -> Path:
            """
            Restore Directory.absolute_path from the on-disk config file.
            """
            print("[validate] Attempting to load config from disk...")
            root = Path(os.getcwd()).resolve()
            config_path = root / "_config" / "mileslib_config.toml"
            print(f"[validate] Looking for config at: {config_path}")

            if not config_path.exists():
                print("[validate] Config file does not exist.")
                raise RuntimeError("Could not initialize from config. Run `mileslib setup` first.")

            print("[debug] Using pdir for cfg_get:", root)
            absolute_root_str = sm.cfg_get("absolute_root", pdir=root, section="mileslib")
            print("[debug] absolute_root from config:", absolute_root_str)

            if absolute_root_str is None:
                raise RuntimeError("Config file is missing 'absolute_root'. Run `mileslib setup` again.")

            absolute_path = Path(absolute_root_str)

            if not absolute_path.exists():
                print("[validate] Config absolute_root path does not exist on filesystem.")
                raise RuntimeError("Could not initialize from config. Run `mileslib setup` first.")

            Directory.absolute_path = absolute_path
            Directory.setup_complete = True
            print(f"[validate] Directory initialized from config: {absolute_path}")
            print(f"Acknowledged Directory class setup: {Directory.setup_complete}")
            print(f"Acknowledged Directory class absolute path: {Directory.absolute_path}")

            return absolute_path

        def _setup():
            print("[validate] Running setup milessubprocess...")
            cmd = ["python", "-m", "mileslib", "setup"]
            print(f"[milessubprocess] Calling: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            print(f"[milessubprocess stdout]\n{result.stdout}")
            print(f"[milessubprocess stderr]\n{result.stderr}")
            print(f"[milessubprocess exit code]: {result.returncode}")

            if result.returncode != 0:
                raise RuntimeError("Critical error with core MilesLib setup logic.")

        if Directory.setup_complete is True and Directory.absolute_path.exists():
            print(f"[validate] Already marked complete: {Directory.absolute_path}")
            return Directory.absolute_path

        print(f"[validate] No class level variables present.")
        try:
            return _load_from_config()
        except RuntimeError as e:
            print(f"[validate] Config load failed: {e}")
            print("[validate] Config not found or invalid. Attempting setup...")
            _setup()
            return _load_from_config()