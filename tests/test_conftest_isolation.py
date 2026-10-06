"""The suite never writes to the developer's working database."""

import conftest
import pytest


def test_session_end_restore_targets_the_scratch_database() -> None:
    # pytest_sessionfinish re-flags seeded accounts in SHARED_DB. By then the working directory
    # is back at the repository, so a relative path would re-flag the developer's own accounts
    # and force a new passphrase at their next login.
    if conftest._WORKDIR is None:
        pytest.skip("SATSA_TESTS_IN_PLACE=1 runs against the working database on purpose")
    assert conftest.SHARED_DB.is_absolute()
    assert conftest.SHARED_DB.is_relative_to(conftest._WORKDIR.resolve())
