import os
from datetime import datetime
from staticmethods import StaticMethods as sm

class MilesLib:
    def __init__(self, pdir: str = os.getcwd()):
        self.sm = sm
        self.pdir = sm.validate_instance_directory(pdir)
        self.launch_time = datetime.utcnow()

if __name__ == "__main__":
    #Miles Lib Instance
    m = MilesLib()