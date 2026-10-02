"""Basic LogSentinel smoke tests."""

import logsentinel


def test_package_version() -> None:
    """Verify that the LogSentinel package exposes its version."""
    assert logsentinel.__version__ == "0.1.0"