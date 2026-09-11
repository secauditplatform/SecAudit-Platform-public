from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.tasks.compliance import _resolve_hosts
from app.tasks.remediation import _resolve_remediation_hosts
from secaudit_core.models import Base, Host, Job, RemediationJob


def _seed_hosts(db: Session) -> None:
    db.add_all(
        [
            Host(name="alice", hostname="10.0.0.1", owner_sub="local:alice", is_active=True),
            Host(name="bob", hostname="10.0.0.2", owner_sub="local:bob", is_active=True),
            Host(name="shared", hostname="10.0.0.3", owner_sub=None, is_active=True),
        ]
    )
    db.commit()


def test_compliance_worker_passes_persisted_owner_scope_to_dynamic_resolver():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        _seed_hosts(db)
        job = Job(
            id=999,
            dynamic_filter={"active_only": True},
            owner_sub="local:alice",
            enforce_host_owner_scope=True,
        )

        assert [host.name for host in _resolve_hosts(db, job)] == ["alice"]
    engine.dispose()


def test_remediation_worker_preserves_privileged_dynamic_targeting():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        _seed_hosts(db)
        job = RemediationJob(
            id=999,
            dynamic_filter={"active_only": True},
            owner_sub="local:admin",
            enforce_host_owner_scope=False,
        )

        assert [host.name for host in _resolve_remediation_hosts(db, job)] == [
            "alice",
            "bob",
            "shared",
        ]
    engine.dispose()
