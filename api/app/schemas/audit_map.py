from pydantic import BaseModel, Field


class AuditMapServiceRead(BaseModel):
    id: int | None = None
    port: int
    protocol: str
    source: str
    confirmed: bool
    status: str
    coverage_reason: str | None = None


class AuditMapNodeRead(BaseModel):
    host_id: int
    name: str
    hostname: str
    ip: str | None = None
    dns: str | None = None
    port: int
    os_type: str | None = None
    site: str | None = None
    environment: str | None = None
    criticality: str | None = None
    tags: list[str]
    status: str
    last_job_run_id: int | None = None
    profile_id: int | None = None
    profile_name: str | None = None
    checks: dict[str, int] | None = None
    x: float | None = None
    y: float | None = None
    subnet: str | None = None
    services: list[AuditMapServiceRead]


class AuditMapGroupRead(BaseModel):
    subnet: str | None = None
    nodes: list[AuditMapNodeRead]


class AuditMapViewGroupRead(BaseModel):
    key: str | None = None
    status: str
    nodes: list[AuditMapNodeRead]


class AuditMapEdgeRead(BaseModel):
    id: int
    source_host_id: int
    source_port: int
    target_host_id: int
    target_port: int


class AuditMapPosition(BaseModel):
    host_id: int
    x: float = Field(..., ge=-100000, le=100000)
    y: float = Field(..., ge=-100000, le=100000)


class AuditMapProfileRead(BaseModel):
    id: int
    name: str


class AuditMapRead(BaseModel):
    site: str | None = None
    sites: list[str]
    has_unassigned: bool
    truncated: bool
    groups: list[AuditMapGroupRead]
    views: dict[str, list[AuditMapViewGroupRead]]
    layouts: dict[str, list[AuditMapPosition]] = {}
    edges: list[AuditMapEdgeRead]
    profiles: list[AuditMapProfileRead] = []


class AuditMapServiceWrite(BaseModel):
    host_id: int
    port: int = Field(..., ge=1, le=65535)


class AuditMapEdgeWrite(BaseModel):
    source_host_id: int
    source_port: int = Field(..., ge=1, le=65535)
    target_host_id: int
    target_port: int = Field(..., ge=1, le=65535)
