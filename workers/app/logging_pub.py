import json
import logging
from datetime import UTC, datetime

import redis
from secaudit_core.redis_client import sync_redis
from secaudit_core.settings import SecAuditSettings

logger = logging.getLogger(__name__)
_settings = SecAuditSettings()


def _redis_client() -> redis.Redis:
    return sync_redis(_settings.redis_url, settings=_settings, decode_responses=True)


def publish_job_log(job_run_id: int, message: str, level: str = "info") -> None:
    payload = json.dumps(
        {
            "job_run_id": job_run_id,
            "level": level,
            "message": message,
            "timestamp": datetime.now(UTC).isoformat(),
        }
    )
    try:
        client = _redis_client()
        client.publish(f"job_run:{job_run_id}", payload)
        client.lpush(f"job_run_logs:{job_run_id}", payload)
        client.expire(f"job_run_logs:{job_run_id}", _settings.job_log_ttl_seconds)
    except Exception:
        logger.exception("Failed to publish job log for run %s", job_run_id)


def publish_audit_flow_log(run_id: int, message: str, level: str = "info") -> None:
    payload = json.dumps(
        {
            "audit_flow_run_id": run_id,
            "level": level,
            "message": message,
            "timestamp": datetime.now(UTC).isoformat(),
        }
    )
    try:
        client = _redis_client()
        client.publish(f"audit_flow_run:{run_id}", payload)
        client.lpush(f"audit_flow_run_logs:{run_id}", payload)
        client.expire(f"audit_flow_run_logs:{run_id}", _settings.job_log_ttl_seconds)
    except Exception:
        logger.exception("Failed to publish AuditFlow log for run %s", run_id)


def publish_remediation_log(remediation_run_id: int, message: str, level: str = "info") -> None:
    payload = json.dumps(
        {
            "remediation_run_id": remediation_run_id,
            "level": level,
            "message": message,
            "timestamp": datetime.now(UTC).isoformat(),
        }
    )
    try:
        client = _redis_client()
        client.publish(f"remediation_run:{remediation_run_id}", payload)
        client.lpush(f"remediation_run_logs:{remediation_run_id}", payload)
        client.expire(
            f"remediation_run_logs:{remediation_run_id}",
            _settings.job_log_ttl_seconds,
        )
    except Exception:
        logger.exception(
            "Failed to publish remediation log for run %s",
            remediation_run_id,
        )
