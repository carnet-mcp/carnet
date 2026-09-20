# One place. `pyproject.toml` reads it; `__init__` re-exports it; the `initialize`
# handshake sends it as `clientInfo.version`. A literal on its own line so setuptools can
# read it without importing anything.
__version__ = "0.1.0"
