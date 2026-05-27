"""Tests for AWS policy validator."""

import json

import pytest
from qontract_utils.aws_policy_validator import (
    AWSPolicyValidationError,
    AWSPolicyValidator,
    validate_aws_policy,
)


@pytest.fixture
def validator() -> AWSPolicyValidator:
    """Create an AWSPolicyValidator instance for testing."""
    return AWSPolicyValidator()


@pytest.fixture
def valid_policy() -> dict:
    """A valid AWS policy for testing."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*",
            }
        ],
    }


def test_valid_policy_dict(validator: AWSPolicyValidator, valid_policy: dict) -> None:
    """Test validation of a valid policy as dict."""
    # Should not raise any exception
    validator.validate_policy_document(valid_policy, "test-policy")


def test_valid_policy_json_string(
    validator: AWSPolicyValidator, valid_policy: dict
) -> None:
    """Test validation of a valid policy as JSON string."""
    # Should not raise any exception
    validator.validate_policy_document(json.dumps(valid_policy), "test-policy")


def test_convenience_function() -> None:
    """Test the convenience validate_aws_policy function."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
    }
    # Should not raise any exception
    validate_aws_policy(policy, "test-policy")


def test_invalid_json(validator: AWSPolicyValidator) -> None:
    """Test validation fails for invalid JSON."""
    invalid_json = '{"Version": "2012-10-17", "Statement": [{'

    with pytest.raises(AWSPolicyValidationError) as exc_info:
        validator.validate_policy_document(invalid_json, "test-policy")

    assert "Invalid JSON syntax" in str(exc_info.value)
    assert exc_info.value.policy_name == "test-policy"


def test_missing_version(validator: AWSPolicyValidator) -> None:
    """Test validation fails when Version is missing."""
    policy = {
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]
    }

    with pytest.raises(AWSPolicyValidationError) as exc_info:
        validator.validate_policy_document(policy, "test-policy")

    assert "Missing required field: 'Version'" in str(exc_info.value)


def test_invalid_version(validator: AWSPolicyValidator) -> None:
    """Test validation fails for invalid version."""
    policy = {
        "Version": "2020-01-01",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
    }

    with pytest.raises(AWSPolicyValidationError) as exc_info:
        validator.validate_policy_document(policy, "test-policy")

    assert "Invalid Version: '2020-01-01'" in str(exc_info.value)


def test_missing_statement(validator: AWSPolicyValidator) -> None:
    """Test validation fails when Statement is missing."""
    policy = {"Version": "2012-10-17"}

    with pytest.raises(AWSPolicyValidationError) as exc_info:
        validator.validate_policy_document(policy, "test-policy")

    assert "Missing required field: 'Statement'" in str(exc_info.value)


def test_unknown_top_level_field(validator: AWSPolicyValidator) -> None:
    """Test validation warns about unknown top-level fields."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
        "UnknownField": "value",
    }

    with pytest.raises(AWSPolicyValidationError) as exc_info:
        validator.validate_policy_document(policy, "test-policy")

    assert "Unknown top-level field: 'UnknownField'" in str(exc_info.value)


def test_statement_invalid_type(validator: AWSPolicyValidator) -> None:
    """Test validation fails when Statement is not dict or list."""
    policy = {"Version": "2012-10-17", "Statement": "invalid"}

    with pytest.raises(AWSPolicyValidationError) as exc_info:
        validator.validate_policy_document(policy, "test-policy")

    assert "Statement must be an object or array" in str(exc_info.value)


def test_statement_missing_effect(validator: AWSPolicyValidator) -> None:
    """Test validation fails when statement is missing Effect."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Action": "s3:GetObject", "Resource": "*"}],
    }

    with pytest.raises(AWSPolicyValidationError) as exc_info:
        validator.validate_policy_document(policy, "test-policy")

    assert "Statement[0]: Missing required field 'Effect'" in str(exc_info.value)


def test_statement_invalid_effect(validator: AWSPolicyValidator) -> None:
    """Test validation fails for invalid Effect value."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Maybe", "Action": "s3:GetObject", "Resource": "*"}],
    }

    with pytest.raises(AWSPolicyValidationError) as exc_info:
        validator.validate_policy_document(policy, "test-policy")

    assert "Invalid Effect 'Maybe'" in str(exc_info.value)


def test_statement_missing_action(validator: AWSPolicyValidator) -> None:
    """Test validation fails when statement has no Action or NotAction."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Resource": "*"}],
    }

    with pytest.raises(AWSPolicyValidationError) as exc_info:
        validator.validate_policy_document(policy, "test-policy")

    assert "Must have either 'Action' or 'NotAction'" in str(exc_info.value)


def test_statement_both_action_and_not_action(validator: AWSPolicyValidator) -> None:
    """Test validation fails when statement has both Action and NotAction."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "NotAction": "s3:DeleteObject",
                "Resource": "*",
            }
        ],
    }

    with pytest.raises(AWSPolicyValidationError) as exc_info:
        validator.validate_policy_document(policy, "test-policy")

    assert "Cannot have both 'Action' and 'NotAction'" in str(exc_info.value)


def test_statement_both_resource_and_not_resource(
    validator: AWSPolicyValidator,
) -> None:
    """Test validation fails when statement has both Resource and NotResource."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
                "NotResource": "arn:aws:s3:::secret-bucket/*",
            }
        ],
    }

    with pytest.raises(AWSPolicyValidationError) as exc_info:
        validator.validate_policy_document(policy, "test-policy")

    assert "Cannot have both 'Resource' and 'NotResource'" in str(exc_info.value)


def test_action_invalid_format(validator: AWSPolicyValidator) -> None:
    """Test validation fails for actions without service:action format."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "InvalidAction", "Resource": "*"}],
    }

    with pytest.raises(AWSPolicyValidationError) as exc_info:
        validator.validate_policy_document(policy, "test-policy")

    assert "must have format 'service:action'" in str(exc_info.value)


def test_s3_action_validation(validator: AWSPolicyValidator) -> None:
    """Test validation of S3 actions against official AWS actions."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObjekt",  # Invalid S3 action
                "Resource": "*",
            }
        ],
    }

    with pytest.raises(AWSPolicyValidationError) as exc_info:
        validator.validate_policy_document(policy, "test-policy")

    assert "Invalid S3 action 'GetObjekt'" in str(exc_info.value)
    assert "not a valid AWS S3 action" in str(exc_info.value)


def test_valid_s3_actions(validator: AWSPolicyValidator) -> None:
    """Test that valid S3 actions pass validation."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:ListBucket",
                    "s3:DeleteObject",
                    "s3:GetObjectAcl",
                    "s3:PutObjectAcl",
                    "s3:ListAllMyBuckets",
                ],
                "Resource": "*",
            }
        ],
    }
    # Should not raise any exception
    validator.validate_policy_document(policy, "test-policy")


def test_s3_action_wildcards(validator: AWSPolicyValidator) -> None:
    """Test that S3 action wildcards are allowed."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:*",
                    "s3:Get*",
                    "s3:Put*",
                ],
                "Resource": "*",
            }
        ],
    }
    # Should not raise any exception
    validator.validate_policy_document(policy, "test-policy")


def test_action_array(validator: AWSPolicyValidator) -> None:
    """Test validation works with array of actions."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": "*",
            }
        ],
    }
    # Should not raise any exception
    validator.validate_policy_document(policy, "test-policy")


def test_action_wildcard(validator: AWSPolicyValidator) -> None:
    """Test wildcard actions are valid."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    # Should not raise any exception
    validator.validate_policy_document(policy, "test-policy")


def test_invalid_arn_format(validator: AWSPolicyValidator) -> None:
    """Test validation catches invalid ARN format."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3",  # Incomplete ARN
            }
        ],
    }

    with pytest.raises(AWSPolicyValidationError) as exc_info:
        validator.validate_policy_document(policy, "test-policy")

    assert "Invalid ARN format" in str(exc_info.value)


def test_principal_wildcard(validator: AWSPolicyValidator) -> None:
    """Test wildcard principal is valid."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "*",
            }
        ],
    }
    # Should not raise any exception
    validator.validate_policy_document(policy, "test-policy")


@pytest.mark.parametrize(
    ("principal_type", "principal_value", "action"),
    [
        ("AWS", "arn:aws:iam::123456789012:user/testuser", "s3:GetObject"),
        ("Service", "lambda.amazonaws.com", "sts:AssumeRole"),
    ],
)
def test_valid_principal_types(
    validator: AWSPolicyValidator,
    principal_type: str,
    principal_value: str,
    action: str,
) -> None:
    """Test validation of valid principal types."""
    statement: dict[str, str | dict[str, str]] = {
        "Effect": "Allow",
        "Principal": {principal_type: principal_value},
        "Action": action,
    }

    # Add Resource field for non-AssumeRole actions
    if action != "sts:AssumeRole":
        statement["Resource"] = "*"

    policy = {
        "Version": "2012-10-17",
        "Statement": [statement],
    }

    # Should not raise any exception
    validator.validate_policy_document(policy, "test-policy")


def test_principal_unknown_type(validator: AWSPolicyValidator) -> None:
    """Test validation fails for unknown principal type."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"UnknownType": "value"},
                "Action": "s3:GetObject",
                "Resource": "*",
            }
        ],
    }

    with pytest.raises(AWSPolicyValidationError) as exc_info:
        validator.validate_policy_document(policy, "test-policy")

    assert "Unknown principal type" in str(exc_info.value)


def test_principal_string_instead_of_object(validator: AWSPolicyValidator) -> None:
    """Test validation fails when principal is string instead of object."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "arn:aws:iam::123456789012:user/testuser",
                "Action": "s3:GetObject",
                "Resource": "*",
            }
        ],
    }

    with pytest.raises(AWSPolicyValidationError) as exc_info:
        validator.validate_policy_document(policy, "test-policy")

    assert "Principal should be an object with principal type" in str(exc_info.value)


def test_single_statement_as_object(validator: AWSPolicyValidator) -> None:
    """Test validation works when Statement is a single object instead of array."""
    policy = {
        "Version": "2012-10-17",
        "Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
    }
    # Should not raise any exception
    validator.validate_policy_document(policy, "test-policy")


def test_multiple_errors(validator: AWSPolicyValidator) -> None:
    """Test that multiple validation errors are collected and reported."""
    policy = {
        "Version": "invalid-version",
        "Statement": [
            {
                "Effect": "Maybe",  # Invalid effect
                "Action": "InvalidAction",  # Invalid action format
                "Resource": "arn:aws:s3",  # Invalid ARN
            }
        ],
        "UnknownField": "value",  # Unknown field
    }

    with pytest.raises(AWSPolicyValidationError) as exc_info:
        validator.validate_policy_document(policy, "test-policy")

    error_msg = str(exc_info.value)
    assert "Invalid Version" in error_msg
    assert "Invalid Effect" in error_msg
    assert "must have format 'service:action'" in error_msg
    assert "Invalid ARN format" in error_msg
    assert "Unknown top-level field" in error_msg


def test_bucket_policy_example(validator: AWSPolicyValidator) -> None:
    """Test validation of a realistic S3 bucket policy."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowPublicRead",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-public-bucket/*",
            }
        ],
    }
    # Should not raise any exception
    validator.validate_policy_document(policy, "bucket-policy")


def test_iam_role_policy_example(validator: AWSPolicyValidator) -> None:
    """Test validation of a realistic IAM role policy."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                "Resource": "arn:aws:logs:*:*:*",
            },
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*",
            },
        ],
    }
    # Should not raise any exception
    validator.validate_policy_document(policy, "lambda-execution-role")


def test_assume_role_policy_example(validator: AWSPolicyValidator) -> None:
    """Test validation of a realistic assume role policy."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    # Should not raise any exception
    validator.validate_policy_document(policy, "assume-role-policy")


# Additional integration test scenarios


def test_malformed_policy_that_causes_aws_error() -> None:
    """Test the specific case mentioned in the requirements."""
    malformed_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObjekt",  # This invalid action causes AWS MalformedPolicy error
                "Resource": "arn:aws:s3:::my-bucket/*",
            }
        ],
    }

    with pytest.raises(AWSPolicyValidationError) as exc_info:
        validate_aws_policy(malformed_policy, "bucket-policy")

    assert "Invalid S3 action 'GetObjekt'" in str(exc_info.value)
    assert "not a valid AWS S3 action" in str(exc_info.value)


def test_complex_policy_with_conditions() -> None:
    """Test a complex policy with conditions passes validation."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": "arn:aws:s3:::my-bucket/*",
                "Condition": {
                    "StringEquals": {"s3:ExistingObjectTag/Environment": "production"}
                },
            }
        ],
    }
    # Should not raise any exception
    validate_aws_policy(policy, "conditional-policy")
