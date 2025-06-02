from util import milesutil as mu

def check_dependencies(tool):
    print(f"[diagnostics] Checking tools: {tool}")
    if tool == "all":
        try:
            mu.Dependency.ensure_all()
        except Exception as e:
            raise RuntimeError(f"Failed diagnostics check!: {e}")
    try:
        mu.Dependency.ensure(tool)
    except Exception as e:
        raise RuntimeError(f"Failed diagnostics check!: {e}")