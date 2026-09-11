"""S3-compatible object storage for scheduled report delivery."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from secaudit_core.settings import SecAuditSettings

logger = logging.getLogger(__name__)


def upload_report_object(
    *,
    settings: SecAuditSettings,
    key: str,
    content: bytes,
    content_type: str,
    bucket: str | None = None,
    access_key: str | None = None,
    secret_key: str | None = None,
    endpoint_url: str | None = None,
) -> str:
    try:
        import boto3
        from botocore.config import Config
    except ImportError as exc:
        raise RuntimeError("boto3 is required for S3 report delivery") from exc

    resolved_bucket = bucket or settings.s3_bucket
    if not resolved_bucket:
        raise ValueError("S3 bucket is not configured")

    resolved_access_key = access_key or settings.s3_access_key
    resolved_secret_key = secret_key or settings.s3_secret_key
    if not resolved_access_key or not resolved_secret_key:
        raise ValueError("S3 credentials are not configured")

    resolved_endpoint = endpoint_url or settings.s3_endpoint_url
    prefix = (settings.s3_prefix or "reports").strip("/")
    object_key = f"{prefix}/{key.lstrip('/')}" if prefix else key.lstrip("/")

    client_kwargs: dict = {
        "service_name": "s3",
        "aws_access_key_id": resolved_access_key,
        "aws_secret_access_key": resolved_secret_key,
        "region_name": settings.s3_region,
        "config": Config(signature_version="s3v4"),
    }
    if resolved_endpoint:
        client_kwargs["endpoint_url"] = resolved_endpoint

    client = boto3.client(**client_kwargs)
    client.put_object(
        Bucket=resolved_bucket,
        Key=object_key,
        Body=content,
        ContentType=content_type,
    )
    if resolved_endpoint:
        base = resolved_endpoint.rstrip("/")
        return f"{base}/{resolved_bucket}/{object_key}"
    return f"s3://{resolved_bucket}/{object_key}"
