---
resource: s3
module: s3_secure_bucket
tags_covered: [encryption, public-access-block, versioning, lifecycle]
free_tier_friendly: true
---

# Module: Secure S3 Bucket

Use for: general-purpose private object storage (logs, artifacts, backups, static data).
Do NOT use for: public static website hosting (blocked by policy).

## When to pick this pattern
The request mentions a bucket, object storage, log storage, audit logs, backups, or artifacts.

Keywords: S3 bucket, object storage, store logs, audit logs, backups, artifacts, private, encrypted, versioned.

## Terraform

```hcl
terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

variable "project"     { type = string }
variable "environment" { type = string }
variable "owner"       { type = string }
variable "cost_center" { type = string }
variable "purpose"     { type = string }
variable "region" {
  type    = string
  default = "ap-south-1"
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      Owner       = var.owner
      Environment = var.environment
      CostCenter  = var.cost_center
      Project     = var.project
      ManagedBy   = "terraform"
    }
  }
}

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "this" {
  bucket = "${var.project}-${var.environment}-s3-${var.purpose}-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    id     = "expire-noncurrent"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

output "bucket_arn" {
  value = aws_s3_bucket.this.arn
}

output "bucket_id" {
  value = aws_s3_bucket.this.id
}
```

## Notes for the agent
- Adjust `purpose` from the request (e.g. "audit-logs").
- Add KMS encryption only if the request explicitly asks for customer-managed keys (adds cost).
- Checkov may flag missing access logging and cross-region replication; these are acceptable for dev unless the request says otherwise.c