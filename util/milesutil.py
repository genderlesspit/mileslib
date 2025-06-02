import logging

import util.error_handling as error_handling
import util.milesio as milesio
import util.milesprocess as milesprocess
import util.sanitization as sanitization

# Configure module‐level logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

check_types = error_handling.check_types
write = milesio.file.write
ensure_file = milesio.file.ensure
validate_directory = milesio.path.validate_directory
attempt = error_handling.attempt
recall = error_handling.recall
Runner = milesprocess.MilesProcess.Runner
Dependency = milesprocess.MilesProcess.Dependency
PythonDependencies = milesprocess.MilesProcess.PythonDependencies
run = Runner.run
ensure_dependency = staticmethod(milesprocess.ensure_dependency)
ensure_all_dependencies = staticmethod(milesprocess.ensure_all_dependencies)
in_virtualenv = staticmethod(milesprocess.in_virtualenv)
try_import = staticmethod(milesprocess.try_import)
MPath = milesio.Path
MFile = milesio.IO.File
purge = staticmethod(sanitization.Sanitization.purge)
