from milesazure.ids import AzureServicePrincipal


def init_azure(ctx):
    """
    Initializes and validates all Azure identity values for the current project.

    Args:
        ctx: Click context object, must include 'project_name' in ctx.obj.

    Returns:
        dict: A dictionary of all resolved Azure identity values.
    """
    project = ctx.obj.get("project_name")
    if not project:
        raise ValueError("[init_azure] ctx.obj missing 'project_name'")
    print(f"[init_azure] Validating Azure identity for project: {project}")
    AzureServicePrincipal(project)

