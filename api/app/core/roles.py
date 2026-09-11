from app.core.auth import require_roles
from secaudit_core.enums import UserRole
from secaudit_core.rbac import ADMIN_ROLES, OPERATE_ROLES, REMEDIATION_ROLES, REPORTS_ROLES, SCRIPT_ROLES

require_admin = require_roles(*ADMIN_ROLES)
require_operate = require_roles(*OPERATE_ROLES)
require_reports = require_roles(*REPORTS_ROLES)
require_remediation = require_roles(*REMEDIATION_ROLES)
require_scripts = require_roles(*SCRIPT_ROLES)
