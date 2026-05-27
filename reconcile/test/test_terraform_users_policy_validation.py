"""Integration tests for AWS policy validation in terraform_users using Access Analyzer."""

from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from qontract_utils.aws_policy_validator import AWSPolicyValidationError

from reconcile.terraform_users import _validate_aws_policies_in_roles


@pytest.fixture
def mock_accounts() -> list[dict[str, Any]]:
    """Fixture providing mock AWS accounts."""
    return [
        {
            "name": "test-account-1",
            "automationToken": {
                "path": "vault/path/to/token",
            },
            "resourcesDefaultRegion": "us-east-1",
        }
    ]


@pytest.fixture
def mock_settings() -> dict[str, Any]:
    """Fixture providing mock app-interface settings."""
    return {
        "vault": True,
    }


@patch("reconcile.terraform_users.SecretReader")
@patch("boto3.client")
def test_validate_aws_policies_in_roles_valid_policies(
    mock_boto_client: MagicMock,
    mock_secret_reader: MagicMock,
    mock_accounts: list[dict[str, Any]],
    mock_settings: dict[str, Any],
) -> None:
    """Test validation passes for roles with valid policies."""
    # Mock Secret Reader to return AWS credentials
    mock_secret_reader.return_value.read_all.return_value = {
        "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    }

    # Mock Access Analyzer to return no findings
    mock_aa = MagicMock()
    mock_aa.get_paginator.return_value.paginate.return_value = [{"findings": []}]
    mock_boto_client.return_value = mock_aa

    roles = [
        {
            "name": "test-role-1",
            "user_policies": [
                {
                    "name": "s3-access",
                    "policy": """{
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "s3:GetObject",
                                "Resource": "arn:aws:s3:::my-bucket/*"
                            }
                        ]
                    }""",
                    "account": {"name": "test-account-1"},
                }
            ],
        },
        {
            "name": "test-role-2",
            "user_policies": [
                {
                    "name": "ec2-access",
                    "policy": """{
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": ["ec2:DescribeInstances", "ec2:DescribeImages"],
                                "Resource": "*"
                            }
                        ]
                    }""",
                    "account": {"name": "test-account-1"},
                }
            ],
        },
    ]

    # Should not raise any exception
    _validate_aws_policies_in_roles(roles, mock_accounts, mock_settings)

    # Verify Access Analyzer was called for both policies
    assert mock_aa.get_paginator.call_count == 2


@patch("boto3.client")
def test_validate_aws_policies_in_roles_no_policies(
    mock_boto_client: MagicMock,
    mock_accounts: list[dict[str, Any]],
    mock_settings: dict[str, Any],
) -> None:
    """Test validation passes when there are no policies."""
    roles: list[dict[str, Any]] = [
        {"name": "test-role-1", "user_policies": None},
        {"name": "test-role-2", "user_policies": []},
    ]

    # Should not raise any exception
    _validate_aws_policies_in_roles(roles, mock_accounts, mock_settings)

    # boto3 client should never be created when there are no policies
    mock_boto_client.assert_not_called()


@patch("reconcile.terraform_users.SecretReader")
@patch("boto3.client")
def test_validate_aws_policies_in_roles_invalid_policy(
    mock_boto_client: MagicMock,
    mock_secret_reader: MagicMock,
    mock_accounts: list[dict[str, Any]],
    mock_settings: dict[str, Any],
) -> None:
    """Test validation fails for roles with invalid policies."""
    # Mock Secret Reader to return AWS credentials
    mock_secret_reader.return_value.read_all.return_value = {
        "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    }

    # Mock Access Analyzer to return ERROR finding
    mock_aa = MagicMock()
    mock_aa.get_paginator.return_value.paginate.return_value = [
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
    mock_boto_client.return_value = mock_aa

    roles = [
        {
            "name": "test-role-1",
            "user_policies": [
                {
                    "name": "bad-policy",
                    "policy": """{
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "s3:*",
                                "Resource": "*"
                            }
                        ]
                    }""",
                    "account": {"name": "test-account-1"},
                }
            ],
        }
    ]

    with pytest.raises(AWSPolicyValidationError) as exc_info:
        _validate_aws_policies_in_roles(roles, mock_accounts, mock_settings)

    assert "user_policy-bad-policy" in str(exc_info.value)
    assert "MISSING_VERSION" in str(exc_info.value)


@patch("reconcile.terraform_users.SecretReader")
@patch("boto3.client")
def test_validate_aws_policies_in_roles_multiple_invalid_policies(
    mock_boto_client: MagicMock,
    mock_secret_reader: MagicMock,
    mock_accounts: list[dict[str, Any]],
    mock_settings: dict[str, Any],
) -> None:
    """Test validation fails on the first invalid policy."""
    # Mock Secret Reader to return AWS credentials
    mock_secret_reader.return_value.read_all.return_value = {
        "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    }

    # Mock Access Analyzer to return ERROR for the first call
    mock_aa = MagicMock()
    mock_aa.get_paginator.return_value.paginate.return_value = [
        {
            "findings": [
                {
                    "findingType": "ERROR",
                    "issueCode": "INVALID_ACTION",
                    "findingDetails": "The action is not valid.",
                }
            ]
        }
    ]
    mock_boto_client.return_value = mock_aa

    roles = [
        {
            "name": "test-role-1",
            "user_policies": [
                {
                    "name": "policy1",
                    "policy": '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "invalid:action", "Resource": "*"}]}',
                    "account": {"name": "test-account-1"},
                },
                {
                    "name": "policy2",
                    "policy": '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}',
                    "account": {"name": "test-account-1"},
                },
            ],
        }
    ]

    # Should fail on first invalid policy and not validate the second
    with pytest.raises(AWSPolicyValidationError):
        _validate_aws_policies_in_roles(roles, mock_accounts, mock_settings)

    assert mock_aa.get_paginator.call_count == 1


@patch("reconcile.terraform_users.SecretReader")
@patch("boto3.client")
def test_validate_aws_policies_handles_dict_policy(
    mock_boto_client: MagicMock,
    mock_secret_reader: MagicMock,
    mock_accounts: list[dict[str, Any]],
    mock_settings: dict[str, Any],
) -> None:
    """Test validation handles policy as dict (not JSON string)."""
    # Mock Secret Reader to return AWS credentials
    mock_secret_reader.return_value.read_all.return_value = {
        "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    }

    mock_aa = MagicMock()
    mock_aa.get_paginator.return_value.paginate.return_value = [{"findings": []}]
    mock_boto_client.return_value = mock_aa

    roles = [
        {
            "name": "test-role-1",
            "user_policies": [
                {
                    "name": "dict-policy",
                    "policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "s3:GetObject",
                                "Resource": "*",
                            }
                        ],
                    },
                    "account": {"name": "test-account-1"},
                }
            ],
        }
    ]

    # Should not raise any exception
    _validate_aws_policies_in_roles(roles, mock_accounts, mock_settings)

    # Verify Access Analyzer was called
    mock_aa.get_paginator.assert_called_once()
