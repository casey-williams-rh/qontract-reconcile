"""Integration tests for AWS policy validation in terraform_users."""

from typing import Any

import pytest
from qontract_utils.aws_policy_validator import AWSPolicyValidationError

from reconcile.terraform_users import _validate_aws_policies_in_roles


class TestTerraformUsersValidation:
    """Test AWS policy validation in the terraform_users integration."""

    def test_validate_aws_policies_in_roles_valid_policies(self) -> None:
        """Test validation passes for roles with valid policies."""
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
                    }
                ],
            },
        ]

        # Should not raise any exception
        _validate_aws_policies_in_roles(roles)

    def test_validate_aws_policies_in_roles_no_policies(self) -> None:
        """Test validation passes for roles without policies."""
        roles: list[dict[str, Any]] = [
            {"name": "test-role-1", "user_policies": None},
            {"name": "test-role-2", "user_policies": []},
            {
                "name": "test-role-3"
                # No user_policies key
            },
        ]

        # Should not raise any exception
        _validate_aws_policies_in_roles(roles)

    def test_validate_aws_policies_in_roles_invalid_policy_json(self) -> None:
        """Test validation fails for roles with invalid JSON policies."""
        roles = [
            {
                "name": "test-role-1",
                "user_policies": [
                    {
                        "name": "invalid-json-policy",
                        "policy": """{
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "s3:GetObject",
                                    "Resource": "arn:aws:s3:::my-bucket/*"
                                }
                            ]
                        """,  # Missing closing brace
                    }
                ],
            }
        ]

        with pytest.raises(AWSPolicyValidationError) as exc_info:
            _validate_aws_policies_in_roles(roles)

        error_msg = str(exc_info.value)
        assert "test-role-1" in error_msg
        assert "invalid-json-policy" in error_msg
        assert "Policy validation failed in terraform_users integration" in error_msg

    def test_validate_aws_policies_in_roles_malformed_action(self) -> None:
        """Test validation fails for roles with malformed S3 actions."""
        roles = [
            {
                "name": "test-role-1",
                "user_policies": [
                    {
                        "name": "bucket-access",
                        "policy": """{
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "s3:GetObjekt",
                                    "Resource": "arn:aws:s3:::my-bucket/*"
                                }
                            ]
                        }""",
                    }
                ],
            }
        ]

        with pytest.raises(AWSPolicyValidationError) as exc_info:
            _validate_aws_policies_in_roles(roles)

        error_msg = str(exc_info.value)
        assert "test-role-1" in error_msg
        assert "bucket-access" in error_msg
        assert "Policy validation failed in terraform_users integration" in error_msg

    def test_validate_aws_policies_in_roles_multiple_invalid_policies(self) -> None:
        """Test validation fails on first invalid policy and provides context."""
        roles = [
            {
                "name": "valid-role",
                "user_policies": [
                    {
                        "name": "valid-policy",
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
                    }
                ],
            },
            {
                "name": "invalid-role",
                "user_policies": [
                    {
                        "name": "invalid-policy",
                        "policy": """{
                            "Version": "invalid-version",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "s3:GetObject",
                                    "Resource": "*"
                                }
                            ]
                        }""",
                    }
                ],
            },
        ]

        with pytest.raises(AWSPolicyValidationError) as exc_info:
            _validate_aws_policies_in_roles(roles)

        error_msg = str(exc_info.value)
        assert "invalid-role" in error_msg
        assert "invalid-policy" in error_msg

    def test_validate_aws_policies_in_roles_missing_policy_document(self) -> None:
        """Test validation skips policies without policy documents."""
        roles = [
            {
                "name": "test-role-1",
                "user_policies": [
                    {"name": "policy-without-document", "policy": None},
                    {"name": "policy-with-empty-document", "policy": ""},
                    {
                        "name": "valid-policy",
                        "policy": """{
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "s3:GetObject",
                                    "Resource": "*"
                                }
                            ]
                        }""",
                    },
                ],
            }
        ]

        # Should not raise exception - skips None/empty policies but validates the valid one
        _validate_aws_policies_in_roles(roles)

    def test_validate_aws_policies_complex_valid_policy(self) -> None:
        """Test validation of a complex but valid policy."""
        roles = [
            {
                "name": "complex-role",
                "user_policies": [
                    {
                        "name": "complex-policy",
                        "policy": """{
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Sid": "AllowS3Access",
                                    "Effect": "Allow",
                                    "Action": [
                                        "s3:GetObject",
                                        "s3:PutObject",
                                        "s3:ListBucket"
                                    ],
                                    "Resource": [
                                        "arn:aws:s3:::my-bucket",
                                        "arn:aws:s3:::my-bucket/*"
                                    ]
                                },
                                {
                                    "Sid": "AllowKMSDecryption",
                                    "Effect": "Allow",
                                    "Action": "kms:Decrypt",
                                    "Resource": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
                                    "Condition": {
                                        "StringEquals": {
                                            "kms:ViaService": "s3.us-east-1.amazonaws.com"
                                        }
                                    }
                                }
                            ]
                        }""",
                    }
                ],
            }
        ]

        # Should not raise any exception
        _validate_aws_policies_in_roles(roles)

    def test_validate_aws_policies_specific_aws_error_case(self) -> None:
        """Test the specific case that causes 'MalformedPolicy: Policy has invalid action' in AWS."""
        roles = [
            {
                "name": "bucket-policy-role",
                "user_policies": [
                    {
                        "name": "bucket-policy",
                        "policy": """{
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "s3:GetObjekt",
                                    "Resource": "arn:aws:s3:::my-bucket/*"
                                }
                            ]
                        }""",
                    }
                ],
            }
        ]

        with pytest.raises(AWSPolicyValidationError) as exc_info:
            _validate_aws_policies_in_roles(roles)

        error_msg = str(exc_info.value)
        assert "bucket-policy-role" in error_msg
        assert "bucket-policy" in error_msg
        # This should have been caught before hitting AWS
        assert "Policy validation failed in terraform_users integration" in error_msg

    def test_validation_provides_helpful_error_messages(self) -> None:
        """Test that validation errors provide actionable feedback."""
        roles = [
            {
                "name": "my-app-role",
                "user_policies": [
                    {
                        "name": "s3-access-policy",
                        "policy": """{
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "s3:GetObjekt",
                                    "Resource": "arn:aws:s3:::my-app-bucket/*"
                                }
                            ]
                        }""",
                    }
                ],
            }
        ]

        with pytest.raises(AWSPolicyValidationError) as exc_info:
            _validate_aws_policies_in_roles(roles)

        error_msg = str(exc_info.value)
        # Should provide specific guidance
        assert "Invalid S3 action 'GetObjekt'" in error_msg
        assert "did you mean 'GetObject'" in error_msg
        # Should provide context about where the error occurred
        assert "my-app-role" in error_msg
        assert "s3-access-policy" in error_msg
