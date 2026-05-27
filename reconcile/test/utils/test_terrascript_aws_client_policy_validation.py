"""Integration tests for AWS policy validation in TerrascriptClient."""

from unittest.mock import MagicMock, patch

import pytest
from qontract_utils.aws_policy_validator import AWSPolicyValidationError

from reconcile.utils.external_resources import ExternalResourceSpec
from reconcile.utils.terrascript_aws_client import TerrascriptClient


@pytest.fixture
def terrascript_client() -> TerrascriptClient:
    """Create a TerrascriptClient for testing."""
    return TerrascriptClient(
        integration="test-integration",
        integration_prefix="test",
        thread_pool_size=1,
        accounts=[{"name": "test-account", "uid": "123456789"}],
        default_tags={"test": "true"},
        settings={},
    )


@pytest.fixture
def external_resource_spec() -> ExternalResourceSpec:
    """Create an external resource spec for testing."""
    resource = {
        "identifier": "test-resource",
        "provider": "s3",
    }
    provisioner = {"name": "test-account"}
    namespace = {"name": "test-namespace"}
    return ExternalResourceSpec(
        provision_provider="aws",
        provisioner=provisioner,
        resource=resource,
        namespace=namespace,
    )


class TestS3BucketPolicyValidation:
    """Test S3 bucket policy validation in TerrascriptClient."""

    def test_valid_s3_bucket_policy(
        self,
        terrascript_client: TerrascriptClient,
        external_resource_spec: ExternalResourceSpec,
    ) -> None:
        """Test that valid S3 bucket policies pass validation."""
        valid_policy = """{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::my-bucket/*"
                }
            ]
        }"""

        # Mock the S3 bucket resource
        mock_bucket = MagicMock()
        mock_bucket.id = "test-bucket"

        # Should not raise any exception
        result = terrascript_client._populate_tf_resource_s3_bucket_policy(
            external_resource_spec, mock_bucket, valid_policy, {"region": "us-east-1"}
        )

        assert len(result) == 1
        assert result[0].policy == valid_policy

    def test_invalid_s3_bucket_policy_json_syntax(
        self,
        terrascript_client: TerrascriptClient,
        external_resource_spec: ExternalResourceSpec,
    ) -> None:
        """Test that invalid JSON in S3 bucket policy raises validation error."""
        invalid_policy = """{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::my-bucket/*"
                }
            ]
        """  # Missing closing brace

        mock_bucket = MagicMock()

        with pytest.raises(AWSPolicyValidationError) as exc_info:
            terrascript_client._populate_tf_resource_s3_bucket_policy(
                external_resource_spec,
                mock_bucket,
                invalid_policy,
                {"region": "us-east-1"},
            )

        assert "Invalid JSON syntax" in str(exc_info.value)
        assert "bucket_policy-test-resource" in str(exc_info.value)

    def test_invalid_s3_bucket_policy_malformed_action(
        self,
        terrascript_client: TerrascriptClient,
        external_resource_spec: ExternalResourceSpec,
    ) -> None:
        """Test that malformed S3 actions raise validation error."""
        invalid_policy = """{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObjekt",
                    "Resource": "arn:aws:s3:::my-bucket/*"
                }
            ]
        }"""

        mock_bucket = MagicMock()

        with pytest.raises(AWSPolicyValidationError) as exc_info:
            terrascript_client._populate_tf_resource_s3_bucket_policy(
                external_resource_spec,
                mock_bucket,
                invalid_policy,
                {"region": "us-east-1"},
            )

        assert "Invalid S3 action 'GetObjekt'" in str(exc_info.value)
        assert "did you mean 'GetObject'" in str(exc_info.value)


class TestPopulateIAMPolicyValidation:
    """Test IAM policy validation in TerrascriptClient."""

    def test_valid_iam_policy(self, terrascript_client: TerrascriptClient) -> None:
        """Test that valid IAM policies pass validation."""
        valid_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::my-bucket/*",
                }
            ],
        }

        # Should not raise any exception
        terrascript_client.populate_iam_policy(
            "test-account", "test-policy", valid_policy
        )

    def test_invalid_iam_policy(self, terrascript_client: TerrascriptClient) -> None:
        """Test that invalid IAM policies raise validation error."""
        invalid_policy = {
            "Version": "invalid-version",
            "Statement": [
                {"Effect": "Maybe", "Action": "InvalidAction", "Resource": "*"}
            ],
        }

        with pytest.raises(AWSPolicyValidationError) as exc_info:
            terrascript_client.populate_iam_policy(
                "test-account", "test-policy", invalid_policy
            )

        error_msg = str(exc_info.value)
        assert "Invalid Version" in error_msg
        assert "Invalid Effect" in error_msg
        assert "must have format 'service:action'" in error_msg


class TestUserPolicyValidation:
    """Test user policy validation in various contexts."""

    def test_terraform_users_integration_simulation(self) -> None:
        """Simulate the terraform_users integration validation."""
        from qontract_utils.aws_policy_validator import validate_aws_policy

        # Test valid policy
        valid_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:ListBucket"],
                    "Resource": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"],
                }
            ],
        }

        # Should not raise any exception
        validate_aws_policy(valid_policy, "user_policy-test")

    def test_terraform_users_invalid_policy(self) -> None:
        """Test that terraform_users would catch invalid policies."""
        from qontract_utils.aws_policy_validator import validate_aws_policy

        # Test policy with typo that causes AWS "MalformedPolicy" error
        invalid_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObjekt",  # Typo that causes AWS error
                    "Resource": "arn:aws:s3:::my-bucket/*",
                }
            ],
        }

        with pytest.raises(AWSPolicyValidationError) as exc_info:
            validate_aws_policy(invalid_policy, "user_policy-test")

        assert "Invalid S3 action 'GetObjekt'" in str(exc_info.value)
        assert "did you mean 'GetObject'" in str(exc_info.value)


class TestRoleAndInlinePolicyValidation:
    """Test role policy and inline policy validation."""

    def test_populate_tf_resource_role_with_valid_policies(
        self,
        terrascript_client: TerrascriptClient,
        external_resource_spec: ExternalResourceSpec,
    ) -> None:
        """Test IAM role creation with valid role_policy and inline_policy."""
        # Mock add_resources method
        with patch.object(terrascript_client, "add_resources"):
            # Add required fields for role resource
            external_resource_spec.resource.update({
                "assume_role": "lambda.amazonaws.com",
                "tags": {},
                "role_policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "logs:CreateLogGroup",
                            "Resource": "*",
                        }
                    ],
                },
                "inline_policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "s3:GetObject",
                            "Resource": "arn:aws:s3:::my-bucket/*",
                        }
                    ],
                },
            })

            # Should not raise any exception
            terrascript_client.populate_tf_resource_role(external_resource_spec)

    def test_populate_tf_resource_role_with_invalid_role_policy(
        self,
        terrascript_client: TerrascriptClient,
        external_resource_spec: ExternalResourceSpec,
    ) -> None:
        """Test IAM role creation fails with invalid role_policy."""
        external_resource_spec.resource.update({
            "assume_role": "lambda.amazonaws.com",
            "tags": {},
            "role_policy": {
                "Version": "invalid-version",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "logs:CreateLogGroup",
                        "Resource": "*",
                    }
                ],
            },
        })

        with pytest.raises(AWSPolicyValidationError) as exc_info:
            terrascript_client.populate_tf_resource_role(external_resource_spec)

        assert "role_policy-test-resource" in str(exc_info.value)

    def test_populate_tf_resource_role_with_invalid_inline_policy(
        self,
        terrascript_client: TerrascriptClient,
        external_resource_spec: ExternalResourceSpec,
    ) -> None:
        """Test IAM role creation fails with invalid inline_policy."""
        external_resource_spec.resource.update({
            "assume_role": "lambda.amazonaws.com",
            "tags": {},
            "inline_policy": {
                "Version": "invalid-version",
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
                ],
            },
        })

        with pytest.raises(AWSPolicyValidationError) as exc_info:
            terrascript_client.populate_tf_resource_role(external_resource_spec)

        assert "inline_policy-test-resource" in str(exc_info.value)
        assert "Invalid Version" in str(exc_info.value)


class TestPolicyValidationErrorHandling:
    """Test error handling and logging for policy validation."""

    def test_policy_validation_error_contains_policy_name(self) -> None:
        """Test that validation errors include the policy name for easy identification."""
        from qontract_utils.aws_policy_validator import validate_aws_policy

        invalid_policy = {
            "Version": "2012-10-17",
            "Statement": "invalid",  # Should be array or object
        }

        with pytest.raises(AWSPolicyValidationError) as exc_info:
            validate_aws_policy(invalid_policy, "my-specific-policy")

        assert "my-specific-policy" in str(exc_info.value)
        assert exc_info.value.policy_name == "my-specific-policy"

    def test_multiple_validation_errors_collected(self) -> None:
        """Test that multiple validation errors are collected in a single exception."""
        from qontract_utils.aws_policy_validator import validate_aws_policy

        invalid_policy = {
            "Version": "invalid-version",  # Error 1
            "Statement": [
                {
                    "Effect": "Maybe",  # Error 2
                    "Action": "InvalidAction",  # Error 3
                    "Resource": "arn:aws:s3",  # Error 4 - invalid ARN
                }
            ],
            "UnknownField": "value",  # Error 5
        }

        with pytest.raises(AWSPolicyValidationError) as exc_info:
            validate_aws_policy(invalid_policy, "multi-error-policy")

        error_msg = str(exc_info.value)
        # Should contain all errors
        assert "Invalid Version" in error_msg
        assert "Invalid Effect" in error_msg
        assert "must have format 'service:action'" in error_msg
        assert "Invalid ARN format" in error_msg
        assert "Unknown top-level field" in error_msg
