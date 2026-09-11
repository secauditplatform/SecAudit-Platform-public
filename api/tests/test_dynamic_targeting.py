from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from secaudit_core.hosts import resolve_remediation_host_ids
from secaudit_core.models import Base, Host


def test_resolve_remediation_hosts_prefers_explicit():
    class FakeScalars:
        def __init__(self, values):
            self._values = values

        def all(self):
            return self._values

    class FakeResult:
        def __init__(self, values):
            self._values = values

        def scalars(self):
            return FakeScalars(self._values)

    class FakeDb:
        def __init__(self, results):
            self._results = iter(results)

        def execute(self, _stmt):
            return next(self._results)

    db = FakeDb([FakeResult([101, 102])])
    resolved = resolve_remediation_host_ids(
        db,
        remediation_job_id=5,
        dynamic_filter={"tags": ["prod"]},
        owner_sub="local:alice",
        enforce_owner_scope=True,
    )
    assert resolved == [101, 102]


def test_remediation_dynamic_filter_excludes_cross_owner_and_ownerless_hosts():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add_all(
            [
                Host(name="alice", hostname="10.0.0.1", owner_sub="local:alice", is_active=True),
                Host(name="bob", hostname="10.0.0.2", owner_sub="local:bob", is_active=True),
                Host(name="shared", hostname="10.0.0.3", owner_sub=None, is_active=True),
            ]
        )
        db.commit()

        resolved = resolve_remediation_host_ids(
            db,
            remediation_job_id=999,
            dynamic_filter={"active_only": True},
            owner_sub="local:alice",
            enforce_owner_scope=True,
        )

        assert resolved == [1]
    engine.dispose()


def test_remediation_privileged_dynamic_filter_includes_cross_owner_and_shared_hosts():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add_all(
            [
                Host(name="admin", hostname="10.0.0.1", owner_sub="local:admin", is_active=True),
                Host(name="bob", hostname="10.0.0.2", owner_sub="local:bob", is_active=True),
                Host(name="shared", hostname="10.0.0.3", owner_sub=None, is_active=True),
            ]
        )
        db.commit()

        resolved = resolve_remediation_host_ids(
            db,
            remediation_job_id=999,
            dynamic_filter={"active_only": True},
            owner_sub="local:admin",
            enforce_owner_scope=False,
        )

        assert resolved == [1, 2, 3]
    engine.dispose()
