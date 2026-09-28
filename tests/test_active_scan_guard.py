import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agents"))

from active_scan_guard import (  # noqa: E402
    ScanAuthorization,
    TargetEnvironment,
    TargetNotAuthorizedError,
)


def test_rejects_without_own_target_confirmation():
    auth = ScanAuthorization(
        target="http://localhost:8080",
        environment=TargetEnvironment.LOCAL_STAGING,
        confirm_own_target=False,
    )
    with pytest.raises(TargetNotAuthorizedError, match="confirm_own_target"):
        auth.validate()


def test_allows_local_staging_with_confirmation():
    auth = ScanAuthorization(
        target="http://localhost:8080",
        environment=TargetEnvironment.LOCAL_STAGING,
        confirm_own_target=True,
    )
    auth.validate()  # no debe lanzar


def test_rejects_production_without_second_confirmation():
    auth = ScanAuthorization(
        target="https://miapp.com",
        environment=TargetEnvironment.PRODUCTION,
        confirm_own_target=True,
        confirm_production_risk=False,
    )
    with pytest.raises(TargetNotAuthorizedError, match="confirm_production_risk"):
        auth.validate()


def test_allows_production_with_both_confirmations():
    auth = ScanAuthorization(
        target="https://miapp.com",
        environment=TargetEnvironment.PRODUCTION,
        confirm_own_target=True,
        confirm_production_risk=True,
    )
    auth.validate()  # no debe lanzar


def test_production_limits_are_more_conservative_than_staging():
    staging = ScanAuthorization(
        target="x", environment=TargetEnvironment.LOCAL_STAGING, confirm_own_target=True
    )
    production = ScanAuthorization(
        target="x",
        environment=TargetEnvironment.PRODUCTION,
        confirm_own_target=True,
        confirm_production_risk=True,
    )
    assert production.limits.rate_limit < staging.limits.rate_limit
    assert production.limits.concurrency < staging.limits.concurrency
