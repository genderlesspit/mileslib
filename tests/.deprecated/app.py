from tests.mileslib_core import MilesLib

class App:
    def __init__(self, app):
        self.main = MilesLib()
        self.api = API(self)
        self.Routes = Routes(self)

    class API:
        def __init__(self):
            pass

    class Routes:
        def __init(self):
            pass

