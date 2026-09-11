"""Base Celery task with dead-letter capture on permanent failure."""

from __future__ import annotations

from celery import Task

from secaudit_core.dead_letter import format_traceback, persist_dead_letter_from_task
from secaudit_core.settings import SecAuditSettings


class SecAuditTask(Task):
    """Record permanently failed tasks to the dead-letter store."""

    abstract = True

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        settings = SecAuditSettings()
        try:
            persist_dead_letter_from_task(
                database_url=settings.database_url_sync,
                redis_url=settings.redis_url,
                celery_task_id=task_id,
                task_name=self.name,
                delivery_info=getattr(self.request, "delivery_info", None),
                args=args,
                kwargs=kwargs,
                exc=exc,
                traceback_text=format_traceback(einfo),
                retry_count=int(getattr(self.request, "retries", 0) or 0),
            )
        except Exception:
            self.get_logger().exception(
                "Failed to persist dead letter for task %s (%s)", self.name, task_id
            )
        super().on_failure(exc, task_id, args, kwargs, einfo)
