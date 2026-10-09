from app.core.auth import require_roles, require_roles_or_scopes
from secaudit_core.enums import UserRole
from secaudit_core.rbac import ADMIN_ROLES, OPERATE_ROLES, REMEDIATION_ROLES, REPORTS_ROLES, SCRIPT_ROLES

require_admin = require_roles(*ADMIN_ROLES)
require_operate = require_roles_or_scopes(
    *OPERATE_ROLES, scopes=["jobs:run", "inventory:scan"]
)
require_reports = require_roles_or_scopes(
    *REPORTS_ROLES, scopes=["reports:read", "jobs:run"]
)
require_remediation = require_roles(*REMEDIATION_ROLES)
require_scripts = require_roles(*SCRIPT_ROLES)

# Mutating job / inventory surfaces (narrower than require_operate).
require_jobs_run = require_roles_or_scopes(*OPERATE_ROLES, scopes=["jobs:run"])
require_inventory_scan = require_roles_or_scopes(*OPERATE_ROLES, scopes=["inventory:scan"])
