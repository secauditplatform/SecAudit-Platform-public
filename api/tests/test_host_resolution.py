from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from secaudit_core.enums import CheckStatus
from secaudit_core.hosts import resolve_filter_host_ids, resolve_job_targets
from secaudit_core.interpreter import apply_interpreter_rules
from secaudit_core.models import Base, Host


def test_apply_interpreter_rules_from_core_package():
    output = "RULE1= PASS: ok"
    rules = [{"regex": r"(RULE\d+=\s*PASS:.*)", "tech_name": "RULE1"}]
    results = apply_interpreter_rules(output, rules)
    assert results[0]["status"] == CheckStatus.PASS


def test_resolve_job_host_ids_prefers_explicit_hosts():
    class FakeScalars:
        def all(self):
            return [10, 20]

    class FakeResult:
        def scalars(self):
            return FakeScalars()

    class FakeDb:
        def __init__(self, results):
            self._results = iter(results)

        def execute(self, _stmt):
            return next(self._results)

    db = FakeDb([FakeResult()])
    assert resolve_job_targets(
        db,
        job_id=1,
        dynamic_filter=None,
        owner_sub="local:alice",
        enforce_owner_scope=True,
    ) == [10, 20]


def test_resolve_filter_host_ids_without_filter_returns_empty():
    class FakeDb:
        def execute(self, _stmt):
            raise AssertionError("No DB queries expected")

    assert resolve_filter_host_ids(
        FakeDb(),
        None,
        owner_sub="local:alice",
        enforce_owner_scope=True,
    ) == []


def test_compliance_dynamic_filter_excludes_cross_owner_and_ownerless_hosts():
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

        resolved = resolve_job_targets(
            db,
            job_id=999,
            dynamic_filter={"active_only": True},
            owner_sub="local:alice",
            enforce_owner_scope=True,
        )

        assert resolved == [1]
    engine.dispose()


def test_compliance_privileged_dynamic_filter_includes_owned_foreign_and_shared_hosts():
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

        resolved = resolve_job_targets(
            db,
            job_id=999,
            dynamic_filter={"active_only": True},
            owner_sub="local:admin",
            enforce_owner_scope=False,
        )

        assert resolved == [1, 2, 3]
    engine.dispose()


def test_scoped_dynamic_filter_without_owner_fails_closed():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(Host(name="shared", hostname="10.0.0.3", owner_sub=None, is_active=True))
        db.commit()

        assert resolve_job_targets(
            db,
            job_id=999,
            dynamic_filter={"active_only": True},
            owner_sub=None,
            enforce_owner_scope=True,
        ) == []
    engine.dispose()
