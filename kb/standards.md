# Cloud Infrastructure Standards

Applies to every Terraform configuration this agent generates. Rules marked MUST are enforced by guardrail_check; SHOULD rules are guidance.

## Tagging
- Every taggable resource MUST carry: Owner, Environment, CostCenter, Project, ManagedBy.
- ManagedBy MUST be "terraform".
- Environment MUST be one of dev, staging, prod.
- Use the provider-level `default_tags` block so tags are applied consistently, then add resource-specific tags on top.

## Naming
- Pattern: `<project>-<environment>-<resource>-<purpose>`, lowercase, hyphen-separated.
  Example: `billing-dev-s3-audit-logs`.
- S3 bucket names MUST be globally unique: append the account ID or a short random suffix.

## Regions
- Only regions listed in policies.yaml `allowed_regions` may be used.
- If the request names a region outside the allowlist, do not generate; report the violation.
- Default region when unspecified: ap-south-1.

## Security defaults
- All storage MUST be encrypted at rest (S3 SSE, EBS, RDS `storage_encrypted = true`).
- S3 buckets MUST block all public access.
- No security group ingress from 0.0.0.0/0 except ports 80/443 on load balancers.
- IAM roles MUST follow least privilege: no `Action: "*"` with `Resource: "*"`.
- Prefer IAM roles over long-lived access keys.

## Cost
- SHOULD prefer the smallest instance class that fits the request.
- Anything outside the free-tier matrix in policies.yaml must be justified by the request.
- Estimated monthly cost MUST stay under the ceiling in policies.yaml.

## Terraform hygiene
- Pin the AWS provider version (`~> 5.0`) and set `required_version`.
- Use variables for anything environment-specific; no hardcoded account IDs or secrets.
- Every module exposes outputs for IDs/ARNs other resources will need.
