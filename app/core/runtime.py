from time import monotonic

_STARTED_AT = monotonic()

def get_uptime_seconds() -> int:
    """Get the uptime of the application in seconds."""
    return int(monotonic() - _STARTED_AT)