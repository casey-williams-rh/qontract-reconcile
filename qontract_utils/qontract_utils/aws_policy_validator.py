"""AWS IAM Policy validation utilities.

This module provides comprehensive validation for AWS IAM policy documents
to catch malformed policies before they are applied to AWS resources.
"""

from __future__ import annotations

import difflib
import json
from typing import Any, ClassVar

from qontract_utils.exceptions import IntegrationError

# Constants
MIN_ARN_PARTS = 6


class AWSPolicyValidationError(IntegrationError):
    """Raised when an AWS policy document fails validation."""

    def __init__(self, policy_name: str, errors: list[str]) -> None:
        self.policy_name = policy_name
        self.errors = errors
        error_list = "\n  - ".join(errors)
        super().__init__(
            f"Policy validation failed for '{policy_name}':\n  - {error_list}"
        )


class AWSPolicyValidator:
    """Validates AWS IAM policy documents for syntax and common errors."""

    # Valid AWS service prefixes for actions
    VALID_SERVICE_PREFIXES: ClassVar[set[str]] = {
        "s3",
        "ec2",
        "iam",
        "lambda",
        "dynamodb",
        "rds",
        "cloudformation",
        "cloudwatch",
        "logs",
        "sns",
        "sqs",
        "kms",
        "secretsmanager",
        "ssm",
        "sts",
        "organizations",
        "account",
        "apigateway",
        "kinesis",
        "elasticloadbalancing",
        "autoscaling",
        "route53",
        "cloudfront",
        "acm",
        "waf",
        "shield",
        "guardduty",
        "inspector",
        "config",
        "cloudtrail",
        "xray",
        "batch",
        "ecs",
        "eks",
        "fargate",
        "elasticbeanstalk",
        "codebuild",
        "codecommit",
        "codedeploy",
        "codepipeline",
        "codestar",
        "elasticfilesystem",
        "fsx",
        "storagegateway",
        "backup",
        "datasync",
        "transfer",
        "workspaces",
        "appstream",
        "workdocs",
        "workmail",
        "chime",
        "connect",
        "pinpoint",
        "mobiletargeting",
        "ses",
        "machinelearning",
        "sagemaker",
        "comprehend",
        "translate",
        "polly",
        "rekognition",
        "textract",
        "transcribe",
        "forecast",
        "personalize",
        "frauddetector",
        "detective",
        "macie",
        "securityhub",
        "accessanalyzer",
        "wellarchitected",
        "trustedadvisor",
        "health",
        "servicecatalog",
        "marketplace",
        "license-manager",
        "resource-groups",
        "tag",
        "application-autoscaling",
        "applicationinsights",
        "appmesh",
        "appconfig",
        "appflow",
        "amplify",
    }

    # Valid effect values
    VALID_EFFECTS: ClassVar[set[str]] = {"Allow", "Deny"}

    # Common AWS principal types
    VALID_PRINCIPAL_TYPES: ClassVar[set[str]] = {
        "AWS",
        "Service",
        "Federated",
        "CanonicalUser",
    }

    def validate_policy_document(
        self, policy: str | dict[str, Any], policy_name: str = "unknown"
    ) -> None:
        """Validate an AWS policy document.

        Args:
            policy: Policy document as JSON string or dict
            policy_name: Name of the policy for error reporting

        Raises:
            AWSPolicyValidationError: If the policy is malformed
        """
        errors: list[str] = []

        # Parse JSON if string
        if isinstance(policy, str):
            try:
                policy_dict = json.loads(policy)
            except json.JSONDecodeError as e:
                errors.append(f"Invalid JSON syntax: {e}")
                raise AWSPolicyValidationError(policy_name, errors) from e
        else:
            policy_dict = policy

        # Validate policy structure
        errors.extend(self._validate_policy_structure(policy_dict))

        # Validate statements
        if "Statement" in policy_dict:
            statements = policy_dict["Statement"]
            if isinstance(statements, dict):
                statements = [statements]
            elif isinstance(statements, list):
                pass
            else:
                errors.append("Statement must be an object or array")

            if isinstance(statements, list):
                for i, statement in enumerate(statements):
                    errors.extend(self._validate_statement(statement, i))

        if errors:
            raise AWSPolicyValidationError(policy_name, errors)

    @staticmethod
    def _validate_policy_structure(policy: dict[str, Any]) -> list[str]:
        """Validate the top-level policy structure."""
        errors: list[str] = []

        # Check required fields
        if "Version" not in policy:
            errors.append("Missing required field: 'Version'")
        elif policy["Version"] not in {"2008-10-17", "2012-10-17"}:
            errors.append(
                f"Invalid Version: '{policy['Version']}' (should be '2012-10-17' or '2008-10-17')"
            )

        if "Statement" not in policy:
            errors.append("Missing required field: 'Statement'")

        # Check for unknown top-level fields
        valid_fields = {"Version", "Statement", "Id"}
        errors.extend(
            f"Unknown top-level field: '{field}'"
            for field in policy
            if field not in valid_fields
        )

        return errors

    def _validate_statement(self, statement: Any, index: int) -> list[str]:
        """Validate an individual policy statement."""
        errors: list[str] = []
        stmt_prefix = f"Statement[{index}]"

        if not isinstance(statement, dict):
            errors.append(f"{stmt_prefix}: Statement must be an object")
            return errors

        # Validate basic statement structure
        errors.extend(self._validate_statement_basic_fields(statement, stmt_prefix))

        # Validate actions
        errors.extend(self._validate_statement_actions(statement, stmt_prefix))

        # Validate resources
        errors.extend(self._validate_statement_resources(statement, stmt_prefix))

        # Validate principal if present
        if "Principal" in statement:
            errors.extend(
                self._validate_principal(
                    statement["Principal"], f"{stmt_prefix}.Principal"
                )
            )

        # Validate unknown fields
        errors.extend(self._validate_statement_unknown_fields(statement, stmt_prefix))

        return errors

    def _validate_statement_basic_fields(
        self, statement: dict[str, Any], stmt_prefix: str
    ) -> list[str]:
        """Validate basic required fields in statement."""
        errors: list[str] = []

        if "Effect" not in statement:
            errors.append(f"{stmt_prefix}: Missing required field 'Effect'")
        elif statement["Effect"] not in self.VALID_EFFECTS:
            errors.append(
                f"{stmt_prefix}: Invalid Effect '{statement['Effect']}' (must be 'Allow' or 'Deny')"
            )

        return errors

    def _validate_statement_actions(
        self, statement: dict[str, Any], stmt_prefix: str
    ) -> list[str]:
        """Validate action fields in statement."""
        errors: list[str] = []

        # Check for Action or NotAction
        has_action = "Action" in statement
        has_not_action = "NotAction" in statement
        if not has_action and not has_not_action:
            errors.append(f"{stmt_prefix}: Must have either 'Action' or 'NotAction'")
        elif has_action and has_not_action:
            errors.append(f"{stmt_prefix}: Cannot have both 'Action' and 'NotAction'")

        # Validate actions
        if has_action:
            errors.extend(
                self._validate_actions(statement["Action"], f"{stmt_prefix}.Action")
            )
        if has_not_action:
            errors.extend(
                self._validate_actions(
                    statement["NotAction"], f"{stmt_prefix}.NotAction"
                )
            )

        return errors

    def _validate_statement_resources(
        self, statement: dict[str, Any], stmt_prefix: str
    ) -> list[str]:
        """Validate resource fields in statement."""
        errors: list[str] = []

        # Check for Resource or NotResource (not required for some resource-based policies)
        has_resource = "Resource" in statement
        has_not_resource = "NotResource" in statement
        if has_resource and has_not_resource:
            errors.append(
                f"{stmt_prefix}: Cannot have both 'Resource' and 'NotResource'"
            )

        # Validate resources
        if has_resource:
            errors.extend(
                self._validate_resources(
                    statement["Resource"], f"{stmt_prefix}.Resource"
                )
            )
        if has_not_resource:
            errors.extend(
                self._validate_resources(
                    statement["NotResource"], f"{stmt_prefix}.NotResource"
                )
            )

        return errors

    @staticmethod
    def _validate_statement_unknown_fields(
        statement: dict[str, Any], stmt_prefix: str
    ) -> list[str]:
        """Validate unknown fields in statement."""
        valid_fields = {
            "Sid",
            "Effect",
            "Principal",
            "NotPrincipal",
            "Action",
            "NotAction",
            "Resource",
            "NotResource",
            "Condition",
        }
        return [
            f"{stmt_prefix}: Unknown field '{field}'"
            for field in statement
            if field not in valid_fields
        ]

    def _validate_actions(self, actions: Any, field_path: str) -> list[str]:
        """Validate Action or NotAction field."""
        errors: list[str] = []

        if isinstance(actions, str):
            actions = [actions]
        elif not isinstance(actions, list):
            errors.append(f"{field_path}: Must be a string or array of strings")
            return errors

        for i, action in enumerate(actions):
            if not isinstance(action, str):
                errors.append(f"{field_path}[{i}]: Action must be a string")
                continue

            # Check for wildcard
            if action == "*":
                continue

            # Check service:action format
            if ":" not in action:
                errors.append(
                    f"{field_path}[{i}]: Action '{action}' must have format 'service:action'"
                )
                continue

            service, action_name = action.split(":", 1)

            # Validate service prefix
            base_service = service.split("*")[0]  # Handle wildcards like s3*
            if base_service and base_service not in self.VALID_SERVICE_PREFIXES:
                # Only warn about unknown services, don't fail
                pass

            # Check for common typos in S3 actions
            if service == "s3":
                errors.extend(
                    AWSPolicyValidator._validate_s3_action(
                        action_name, f"{field_path}[{i}]"
                    )
                )

        return errors

    @staticmethod
    def _validate_s3_action(action: str, field_path: str) -> list[str]:
        """Validate S3-specific actions against official AWS S3 actions."""
        errors: list[str] = []

        # Valid S3 actions from AWS documentation
        valid_s3_actions = {
            "AbortMultipartUpload",
            "AssociateAccessGrantsIdentityCenter",
            "BypassGovernanceRetention",
            "CompleteMultipartUpload",
            "CreateAccessGrant",
            "CreateAccessGrantsInstance",
            "CreateAccessGrantsLocation",
            "CreateAccessPoint",
            "CreateAccessPointForObjectLambda",
            "CreateBucket",
            "CreateBucketMetadataTableConfiguration",
            "CreateJob",
            "CreateMultiRegionAccessPoint",
            "CreateStorageLensGroup",
            "DeleteAccessGrant",
            "DeleteAccessGrantsInstance",
            "DeleteAccessGrantsInstanceResourcePolicy",
            "DeleteAccessGrantsLocation",
            "DeleteAccessPoint",
            "DeleteAccessPointForObjectLambda",
            "DeleteAccessPointPolicy",
            "DeleteAccessPointPolicyForObjectLambda",
            "DeleteBucket",
            "DeleteBucketMetadataTableConfiguration",
            "DeleteBucketPolicy",
            "DeleteBucketWebsite",
            "DeleteJobTagging",
            "DeleteMultiRegionAccessPoint",
            "DeleteObject",
            "DeleteObjectTagging",
            "DeleteObjectVersion",
            "DeleteObjectVersionTagging",
            "DeleteStorageLensConfiguration",
            "DeleteStorageLensConfigurationTagging",
            "DeleteStorageLensGroup",
            "DescribeJob",
            "DescribeMultiRegionAccessPointOperation",
            "DissociateAccessGrantsIdentityCenter",
            "GetAccelerateConfiguration",
            "GetAccessGrant",
            "GetAccessGrantsInstance",
            "GetAccessGrantsInstanceForPrefix",
            "GetAccessGrantsInstanceResourcePolicy",
            "GetAccessGrantsLocation",
            "GetAccessPoint",
            "GetAccessPointConfigurationForObjectLambda",
            "GetAccessPointForObjectLambda",
            "GetAccessPointPolicy",
            "GetAccessPointPolicyForObjectLambda",
            "GetAccessPointPolicyStatus",
            "GetAccessPointPolicyStatusForObjectLambda",
            "GetAccountPublicAccessBlock",
            "GetAnalyticsConfiguration",
            "GetBucketAcl",
            "GetBucketCORS",
            "GetBucketEncryption",
            "GetBucketIntelligentTieringConfiguration",
            "GetBucketInventoryConfiguration",
            "GetBucketLifecycle",
            "GetBucketLifecycleConfiguration",
            "GetBucketLocation",
            "GetBucketLogging",
            "GetBucketMetadataTableConfiguration",
            "GetBucketMetricsConfiguration",
            "GetBucketNotification",
            "GetBucketNotificationConfiguration",
            "GetBucketObjectLockConfiguration",
            "GetBucketOwnershipControls",
            "GetBucketPolicy",
            "GetBucketPolicyStatus",
            "GetBucketPublicAccessBlock",
            "GetBucketReplication",
            "GetBucketRequestPayment",
            "GetBucketTagging",
            "GetBucketVersioning",
            "GetBucketWebsite",
            "GetEncryptionConfiguration",
            "GetIntelligentTieringConfiguration",
            "GetInventoryConfiguration",
            "GetJobTagging",
            "GetLifecycleConfiguration",
            "GetMetricsConfiguration",
            "GetMultiRegionAccessPoint",
            "GetMultiRegionAccessPointPolicy",
            "GetMultiRegionAccessPointPolicyStatus",
            "GetMultiRegionAccessPointRoutes",
            "GetObject",
            "GetObjectAcl",
            "GetObjectAttributes",
            "GetObjectLegalHold",
            "GetObjectRetention",
            "GetObjectTagging",
            "GetObjectTorrent",
            "GetObjectVersion",
            "GetObjectVersionAcl",
            "GetObjectVersionAttributes",
            "GetObjectVersionTagging",
            "GetObjectVersionTorrent",
            "GetReplicationConfiguration",
            "GetStorageLensConfiguration",
            "GetStorageLensConfigurationTagging",
            "GetStorageLensGroup",
            "InitiateReplication",
            "ListAccessGrants",
            "ListAccessGrantsInstances",
            "ListAccessGrantsLocations",
            "ListAccessPoints",
            "ListAccessPointsForObjectLambda",
            "ListAllMyBuckets",
            "ListBucket",
            "ListBucketAnalyticsConfigurations",
            "ListBucketIntelligentTieringConfigurations",
            "ListBucketInventoryConfigurations",
            "ListBucketMetricsConfigurations",
            "ListBucketMultipartUploads",
            "ListBucketVersions",
            "ListJobs",
            "ListMultipartUploadParts",
            "ListMultiRegionAccessPoints",
            "ListStorageLensConfigurations",
            "ListStorageLensGroups",
            "ObjectOwnerOverrideToBucketOwner",
            "PutAccelerateConfiguration",
            "PutAccessGrantsInstanceResourcePolicy",
            "PutAccessPointConfigurationForObjectLambda",
            "PutAccessPointPolicy",
            "PutAccessPointPolicyForObjectLambda",
            "PutAccessPointPublicAccessBlock",
            "PutAccountPublicAccessBlock",
            "PutAnalyticsConfiguration",
            "PutBucketAcl",
            "PutBucketCORS",
            "PutBucketEncryption",
            "PutBucketIntelligentTieringConfiguration",
            "PutBucketInventoryConfiguration",
            "PutBucketLifecycle",
            "PutBucketLifecycleConfiguration",
            "PutBucketLogging",
            "PutBucketMetadataTableConfiguration",
            "PutBucketMetricsConfiguration",
            "PutBucketNotification",
            "PutBucketNotificationConfiguration",
            "PutBucketObjectLockConfiguration",
            "PutBucketOwnershipControls",
            "PutBucketPolicy",
            "PutBucketPublicAccessBlock",
            "PutBucketReplication",
            "PutBucketRequestPayment",
            "PutBucketTagging",
            "PutBucketVersioning",
            "PutBucketWebsite",
            "PutEncryptionConfiguration",
            "PutIntelligentTieringConfiguration",
            "PutInventoryConfiguration",
            "PutJobTagging",
            "PutLifecycleConfiguration",
            "PutMetricsConfiguration",
            "PutMultiRegionAccessPointPolicy",
            "PutObject",
            "PutObjectAcl",
            "PutObjectLegalHold",
            "PutObjectRetention",
            "PutObjectTagging",
            "PutObjectVersionAcl",
            "PutObjectVersionTagging",
            "PutPublicAccessBlock",
            "PutReplicationConfiguration",
            "PutStorageLensConfiguration",
            "PutStorageLensConfigurationTagging",
            "ReplicateDelete",
            "ReplicateObject",
            "ReplicateTags",
            "RestoreObject",
            "SubmitMultiRegionAccessPointRoutes",
            "UpdateJobPriority",
            "UpdateJobStatus",
            "UploadPart",
            "UploadPartCopy",
        }

        # Check if action is wildcard or valid
        if (
            action != "*"
            and not action.endswith("*")
            and action not in valid_s3_actions
        ):
            # Try to suggest a similar action
            suggestion = AWSPolicyValidator._find_closest_s3_action(
                action, valid_s3_actions
            )
            error_msg = f"{field_path}: Invalid S3 action '{action}' (not a valid AWS S3 action)."
            if suggestion:
                error_msg += f" did you mean '{suggestion}'?"
            error_msg += " Please see https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-actions.html for a list of valid actions."
            errors.append(error_msg)

        return errors

    @staticmethod
    def _find_closest_s3_action(action: str, valid_actions: set[str]) -> str | None:
        """Find the closest matching S3 action using simple string similarity."""
        # Use difflib to find close matches
        close_matches = difflib.get_close_matches(
            action, valid_actions, n=1, cutoff=0.6
        )
        return close_matches[0] if close_matches else None

    @staticmethod
    def _validate_resources(resources: Any, field_path: str) -> list[str]:
        """Validate Resource or NotResource field."""
        errors: list[str] = []

        if isinstance(resources, str):
            resources = [resources]
        elif not isinstance(resources, list):
            errors.append(f"{field_path}: Must be a string or array of strings")
            return errors

        for i, resource in enumerate(resources):
            if not isinstance(resource, str):
                errors.append(f"{field_path}[{i}]: Resource must be a string")
                continue

            # Check for wildcard
            if resource == "*":
                continue

            # Basic ARN format check
            if resource.startswith("arn:"):
                parts = resource.split(":")
                if len(parts) < MIN_ARN_PARTS:
                    errors.append(f"{field_path}[{i}]: Invalid ARN format '{resource}'")

        return errors

    def _validate_principal(self, principal: Any, field_path: str) -> list[str]:
        """Validate Principal field."""
        errors: list[str] = []

        if principal == "*":
            return errors

        if isinstance(principal, str):
            errors.append(
                f"{field_path}: Principal should be an object with principal type, not a string"
            )
            return errors

        if not isinstance(principal, dict):
            errors.append(f"{field_path}: Principal must be '*' or an object")
            return errors

        for principal_type, principal_values in principal.items():
            if principal_type not in self.VALID_PRINCIPAL_TYPES:
                errors.append(f"{field_path}.{principal_type}: Unknown principal type")
                continue

            if isinstance(principal_values, str):
                principal_list = [principal_values]
            elif isinstance(principal_values, list):
                principal_list = principal_values
            else:
                errors.append(
                    f"{field_path}.{principal_type}: Must be a string or array of strings"
                )
                continue

            for i, p in enumerate(principal_list):
                if not isinstance(p, str):
                    errors.append(
                        f"{field_path}.{principal_type}[{i}]: Principal must be a string"
                    )

        return errors


# Convenience function for quick validation
def validate_aws_policy(
    policy: str | dict[str, Any], policy_name: str = "unknown"
) -> None:
    """Validate an AWS policy document.

    Args:
        policy: Policy document as JSON string or dict
        policy_name: Name of the policy for error reporting

    Raises:
        AWSPolicyValidationError: If the policy is malformed
    """
    validator = AWSPolicyValidator()
    validator.validate_policy_document(policy, policy_name)
