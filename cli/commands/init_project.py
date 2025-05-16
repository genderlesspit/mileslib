from mileslib import MilesLib

def run(project_name: str):
    print(f"Initializing project: {project_name}")
    MilesLib(pdir=project_name)