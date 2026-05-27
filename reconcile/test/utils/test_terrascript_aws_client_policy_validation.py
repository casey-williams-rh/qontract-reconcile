"""Integration tests for AWS policy validation using Access Analyzer."""

from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock

import pytest
from qontract_utils.aws_policy_validator import (
    AWSPolicyValidationError,
    validate_aws_policy,
)

if TYPE_CHECKING:
    from pytest_mock import MockerFixture


@pytest.fixture
def mock_access_analyzer(mocker: "MockerFixture") -> MagicMock:
    """Fixture providing a mocked Access Analyzer client."""
    mock_aa = MagicMock()
    # Mock the paginator
    mock_paginator = MagicMock()
    mock_aa.get_paginator.return_value = mock_paginator
    mock_paginator.paginate.return_value = [{"findings": []}]
    mocker.patch("boto3.client", return_value=mock_aa)
    return mock_aa


def test_access_analyzer_valid_policy_passes(
    mock_access_analyzer: MagicMock,
) -> None:
    """Test that valid policies pass validation via Access Analyzer."""
    mock_paginator = mock_access_analyzer.get_paginator.return_value
    mock_paginator.paginate.return_value = [{"findings": []}]

    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
    }

    # Should not raise
    validate_aws_policy(mock_access_analyzer, policy, "test-policy", "IDENTITY_POLICY")

    # Verify Access Analyzer was called with correct parameters
    mock_access_analyzer.get_paginator.assert_called_once_with("validate_policy")
    call_kwargs = mock_paginator.paginate.call_args[1]
    assert call_kwargs["policyType"] == "IDENTITY_POLICY"


def test_access_analyzer_error_finding_raises_exception(
    mock_access_analyzer: MagicMock,
) -> None:
    """Test that ERROR findings raise AWSPolicyValidationError."""
    mock_paginator = mock_access_analyzer.get_paginator.return_value
    mock_paginator.paginate.return_value = [
        {
            "findings": [
                {
                    "findingType": "ERROR",
                    "issueCode": "MISSING_VERSION",
                    "findingDetails": "The policy must include a Version element.",
                }
            ]
        }
    ]

    policy = {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}

    with pytest.raises(AWSPolicyValidationError) as exc_info:
        validate_aws_policy(
            mock_access_analyzer, policy, "test-policy", "IDENTITY_POLICY"
        )

    assert "test-policy" in str(exc_info.value)
    assert "MISSING_VERSION" in str(exc_info.value)


def test_access_analyzer_security_warning_logs_but_does_not_raise(
    mock_access_analyzer: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    """Test that SECURITY_WARNING findings are logged but do not raise an exception."""
    mock_paginator = mock_access_analyzer.get_paginator.return_value
    mock_paginator.paginate.return_value = [
        {
            "findings": [
                {
                    "findingType": "SECURITY_WARNING",
                    "issueCode": "WILDCARD_ACTION",
                    "findingDetails": "Using wildcards in actions can be overly permissive.",
                }
            ]
        }
    ]

    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }

    # Should not raise - security warnings are informational
    validate_aws_policy(mock_access_analyzer, policy, "admin-policy", "IDENTITY_POLICY")

    # Verify security warning was logged
    assert "admin-policy" in caplog.text
    assert "WILDCARD_ACTION" in caplog.text
    assert "SECURITY_WARNING" in caplog.text


def test_access_analyzer_warning_only_does_not_raise(
    mock_access_analyzer: MagicMock,
) -> None:
    """Test that WARNING findings alone do not raise an exception."""
    mock_paginator = mock_access_analyzer.get_paginator.return_value
    mock_paginator.paginate.return_value = [
        {
            "findings": [
                {
                    "findingType": "WARNING",
                    "issueCode": "REDUNDANT_ACTION",
                    "findingDetails": "This action is redundant.",
                }
            ]
        }
    ]

    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
    }

    # Should not raise - warnings are informational only
    validate_aws_policy(mock_access_analyzer, policy, "test-policy", "IDENTITY_POLICY")


def test_access_analyzer_resource_policy_type(
    mock_access_analyzer: MagicMock,
) -> None:
    """Test validation with RESOURCE_POLICY type."""
    mock_paginator = mock_access_analyzer.get_paginator.return_value
    mock_paginator.paginate.return_value = [{"findings": []}]

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*",
            }
        ],
    }

    validate_aws_policy(
        mock_access_analyzer, policy, "bucket-policy", "RESOURCE_POLICY"
    )

    # Verify correct policy type was passed
    call_kwargs = mock_paginator.paginate.call_args[1]
    assert call_kwargs["policyType"] == "RESOURCE_POLICY"


def test_access_analyzer_multiple_findings_collected(
    mock_access_analyzer: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    """Test that multiple validation findings are properly separated - ERRORs raise, SECURITY_WARNINGs log."""
    mock_paginator = mock_access_analyzer.get_paginator.return_value
    mock_paginator.paginate.return_value = [
        {
            "findings": [
                {
                    "findingType": "ERROR",
                    "issueCode": "ERROR_1",
                    "findingDetails": "First error",
                },
                {
                    "findingType": "SECURITY_WARNING",
                    "issueCode": "SECURITY_1",
                    "findingDetails": "Security warning",
                },
                {
                    "findingType": "ERROR",
                    "issueCode": "ERROR_2",
                    "findingDetails": "Second error",
                },
            ]
        }
    ]

    policy = {"Version": "2012-10-17", "Statement": []}

    with pytest.raises(AWSPolicyValidationError) as exc_info:
        validate_aws_policy(mock_access_analyzer, policy, "test", "IDENTITY_POLICY")

    error_msg = str(exc_info.value)
    # ERROR findings should be in the exception
    assert "ERROR_1" in error_msg
    assert "ERROR_2" in error_msg
    assert "First error" in error_msg
    assert "Second error" in error_msg

    # SECURITY_WARNING findings should be logged, not in the exception
    assert "SECURITY_1" in caplog.text
    assert "Security warning" in caplog.text
    assert "SECURITY_WARNING" in caplog.text


def test_terraform_users_valid_user_policies_pass(
    mock_access_analyzer: MagicMock,
    mocker: "MockerFixture",
) -> None:
    """Test that valid user policies in terraform_users pass validation."""
    from reconcile.terraform_users import (
        _validate_aws_policies_in_roles,  # noqa: PLC2701
    )

    # Mock Secret Reader
    mock_secret_reader = mocker.patch("reconcile.terraform_users.SecretReader")
    mock_secret_reader.return_value.read_all.return_value = {
        "aws_access_key_id": "test-access-key-id",
        "aws_secret_access_key": "test-secret-access-key",
    }

    mock_paginator = mock_access_analyzer.get_paginator.return_value
    mock_paginator.paginate.return_value = [{"findings": []}]

    accounts: list[dict[str, Any]] = [
        {
            "name": "test-account-1",
            "automationToken": {"path": "vault/path"},
            "resourcesDefaultRegion": "us-east-1",
        }
    ]

    settings: dict[str, Any] = {"vault": True}

    roles = [
        {
            "name": "test-role",
            "user_policies": [
                {
                    "name": "s3-access",
                    "policy": """{
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Action": "s3:GetObject",
                            "Resource": "*"
                        }]
                    }""",
                    "account": {"name": "test-account-1"},
                }
            ],
        }
    ]

    # Should not raise
    _validate_aws_policies_in_roles(roles, accounts, settings)


def test_terraform_users_invalid_user_policy_raises(
    mock_access_analyzer: MagicMock,
    mocker: "MockerFixture",
) -> None:
    """Test that invalid user policies in terraform_users raise error."""
    from reconcile.terraform_users import (
        _validate_aws_policies_in_roles,  # noqa: PLC2701
    )

    # Mock Secret Reader
    mock_secret_reader = mocker.patch("reconcile.terraform_users.SecretReader")
    mock_secret_reader.return_value.read_all.return_value = {
        "aws_access_key_id": "test-access-key-id",
        "aws_secret_access_key": "test-secret-access-key",
    }

    mock_paginator = mock_access_analyzer.get_paginator.return_value
    mock_paginator.paginate.return_value = [
        {
            "findings": [
                {
                    "findingType": "ERROR",
                    "issueCode": "MISSING_VERSION",
                    "findingDetails": "The policy must include a Version element.",
                }
            ]
        }
    ]

    accounts: list[dict[str, Any]] = [
        {
            "name": "test-account-1",
            "automationToken": {"path": "vault/path"},
            "resourcesDefaultRegion": "us-east-1",
        }
    ]

    settings: dict[str, Any] = {"vault": True}

    roles = [
        {
            "name": "test-role",
            "user_policies": [
                {
                    "name": "bad-policy",
                    "policy": """{
                        "Statement": [{
                            "Effect": "Allow",
                            "Action": "s3:*",
                            "Resource": "*"
                        }]
                    }""",
                    "account": {"name": "test-account-1"},
                }
            ],
        }
    ]

    with pytest.raises(AWSPolicyValidationError) as exc_info:
        _validate_aws_policies_in_roles(roles, accounts, settings)

    assert "user_policy-bad-policy" in str(exc_info.value)


def test_terraform_users_no_policies_does_not_call_validator(
    mock_access_analyzer: MagicMock,
) -> None:
    """Test that roles with no policies don't call the validator."""
    from reconcile.terraform_users import (
        _validate_aws_policies_in_roles,  # noqa: PLC2701
    )

    accounts: list[dict[str, Any]] = []
    settings: dict[str, Any] = {"vault": True}

    roles: list[dict[str, Any]] = [
        {"name": "test-role-1", "user_policies": None},
        {"name": "test-role-2", "user_policies": []},
    ]

    _validate_aws_policies_in_roles(roles, accounts, settings)

    # Validator should not have been called
    mock_access_analyzer.get_paginator.assert_not_called()
