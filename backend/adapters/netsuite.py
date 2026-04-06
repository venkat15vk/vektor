"""
Vektor AI — NetSuite ERP Adapter

Read-only extraction via SuiteQL REST API with Token-Based Authentication.
Maps employees, roles, permissions, and subsidiaries. Detects SoD-relevant
permission pairs critical for SOX compliance.
"""

from __future__ import annotations

import hashlib
import hmac
import time
import urllib.parse
import uuid
from base64 import b64encode
from datetime import datetime, timezone
from typing import Any

import httpx
import structlog

from .base import BaseAdapter
from .models import (
    Assignment,
    GraphSnapshot,
    Permission,
    PermissionType,
    Resource,
    Sensitivity,
    Subject,
    SubjectStatus,
    SubjectType,
    utcnow,
    vektor_id,
)

logger = structlog.get_logger(__name__)

SOURCE = "netsuite"

# ---------------------------------------------------------------------------
# Financial-critical permission keys
# ---------------------------------------------------------------------------
FINANCIAL_PERMISSIONS: dict[str, str] = {
    "TRAN_PURCHORD": "Purchase Orders",
    "TRAN_VENDBILL": "Vendor Bills (AP)",
    "TRAN_VENDPYMT": "Vendor Payments",
    "TRAN_INVOICE": "Invoices (AR)",
    "TRAN_CUSTPYMT": "Customer Payments",
    "TRAN_JOURNAL": "Journal Entries (GL)",
    "TRAN_PAYROLL": "Payroll",
    "LIST_VENDOR": "Vendor Master",
    "LIST_CUSTJOB": "Customer Master",
    "LIST_ACCOUNT": "Chart of Accounts",
    "ADMI_SETUP": "Setup / Configuration",
    "ADMI_ACCTPERIODS": "Accounting Periods",
    "REPT_FINANCIALS": "Financial Reports",
}

SOD_PAIRS: list[tuple[str, str]] = [
    ("TRAN_PURCHORD", "TRAN_VENDPYMT"),     # create PO + pay vendor
    ("LIST_VENDOR", "TRAN_VENDBILL"),        # create vendor + create bill
    ("TRAN_VENDBILL", "TRAN_VENDPYMT"),      # create bill + pay bill
    ("TRAN_JOURNAL", "ADMI_ACCTPERIODS"),    # create JE + close period
    ("TRAN_CUSTPYMT", "TRAN_INVOICE"),       # create invoice + receive payment
    ("LIST_ACCOUNT", "TRAN_JOURNAL"),         # modify CoA + create JE
]

# Permission levels in NetSuite
PERM_LEVELS: dict[int, str] = {
    0: "none",
    1: "view",
    2: "create",
    3: "edit",
    4: "full",
}


class NetSuiteAdapter(BaseAdapter):
    """Read-only adapter for NetSuite ERP via SuiteQL REST API."""

    source_name: str = SOURCE

    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None
        self._account_id: str = ""
        self._consumer_key: str = ""
        self._consumer_secret: str = ""
        self._token_id: str = ""
        self._token_secret: str = ""
        self._base_url: str = ""

    # ---- lifecycle ---------------------------------------------------------

    async def connect(self, credentials: dict) -> None:
        """
        Establish connection with Token-Based Authentication.

        Expected keys: account_id, consumer_key, consumer_secret, token_id, token_secret
        """
        self._account_id = credentials["account_id"].replace("-", "_").upper()
        self._consumer_key = credentials["consumer_key"]
        self._consumer_secret = credentials["consumer_secret"]
        self._token_id = credentials["token_id"]
        self._token_secret = credentials["token_secret"]

        # NetSuite REST URL format
        account_slug = self._account_id.lower().replace("_", "-")
        self._base_url = f"https://{account_slug}.suitetalk.api.netsuite.com"

        logger.info("netsuite.connect", account_id=self._account_id)

        self._client = httpx.AsyncClient(timeout=60.0)

        if not await self.test_connection():
            await self.disconnect()
            raise ConnectionError("NetSuite connection verification failed")

        logger.info("netsuite.connected", account_id=self._account_id)

    async def test_connection(self) -> bool:
        try:
            results = await self._suiteql("SELECT id FROM employee WHERE ROWNUM <= 1")
            return results is not None
        except Exception as exc:
            logger.warning("netsuite.test_connection_failed", error=str(exc))
            return False

    async def disconnect(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None
        logger.info("netsuite.disconnected")

    # ---- extraction --------------------------------------------------------

    async def extract(self) -> GraphSnapshot:
        if self._client is None:
            raise RuntimeError("Adapter not connected — call connect() first")

        logger.info("netsuite.extract.start")

        subjects: list[Subject] = []
        permissions: list[Permission] = []
        resources: list[Resource] = []
        assignments: list[Assignment] = []

        # 1. Employees
        employees = await self._suiteql(
            "SELECT id, email, firstname, lastname, isinactive, "
            "department, supervisor, title, hiredate "
            "FROM employee"
        )
        for emp in employees:
            subj = self._map_employee(emp)
            subjects.append(subj)

        # 2. Roles and their permissions
        roles_raw = await self._suiteql(
            "SELECT r.id, r.name FROM role r"
        )
        role_perms_raw = await self._suiteql(
            "SELECT rp.role, rp.permkey, rp.permlevel "
            "FROM rolepermissions rp"
        )

        # Build role permission map
        role_perm_map: dict[str, list[dict]] = {}
        for rp in role_perms_raw:
            role_id = str(rp.get("role", ""))
            role_perm_map.setdefault(role_id, []).append(rp)

        # Create Permission objects for each role
        role_permission_objects: dict[str, Permission] = {}
        for role in roles_raw:
            role_id = str(role.get("id", ""))
            role_name = role.get("name", f"Role-{role_id}")
            perms_for_role = role_perm_map.get(role_id, [])

            actions: list[str] = []
            risk_keywords: list[str] = []
            is_privileged = False

            for rp in perms_for_role:
                permkey = rp.get("permkey", "")
                permlevel = int(rp.get("permlevel", 0))
                level_name = PERM_LEVELS.get(permlevel, "unknown")

                action = f"netsuite:{permkey}.{level_name}"
                actions.append(action)

                if permkey in FINANCIAL_PERMISSIONS:
                    risk_keywords.append(permkey)
                    if permlevel >= 2:  # create or higher
                        is_privileged = True

                if permkey in ("ADMI_SETUP", "ADMI_ACCTPERIODS"):
                    is_privileged = True
                    risk_keywords.append("admin")

            perm = Permission(
                id=vektor_id(SOURCE, f"role:{role_id}"),
                source=SOURCE,
                name=role_name,
                type=PermissionType.ROLE,
                actions=actions,
                is_privileged=is_privileged,
                risk_keywords=sorted(set(risk_keywords)),
                attributes={
                    "netsuite_role_id": role_id,
                    "permission_keys": [rp.get("permkey") for rp in perms_for_role],
                    "permission_levels": {
                        rp.get("permkey"): int(rp.get("permlevel", 0))
                        for rp in perms_for_role
                    },
                },
            )
            permissions.append(perm)
            role_permission_objects[role_id] = perm

        # 3. Employee → Role assignments
        emp_roles = await self._suiteql(
            "SELECT er.entity AS employee_id, er.role AS role_id "
            "FROM employeeroles er"
        )
        for er in emp_roles:
            emp_id = str(er.get("employee_id", ""))
            role_id = str(er.get("role_id", ""))
            subj_id = vektor_id(SOURCE, f"emp:{emp_id}")
            perm = role_permission_objects.get(role_id)
            if perm:
                assignments.append(
                    Assignment(
                        subject_id=subj_id,
                        permission_id=perm.id,
                        source=SOURCE,
                        is_active=True,
                        granted_by="netsuite",
                    )
                )

        # 4. Subsidiaries → Resources
        try:
            subsidiaries = await self._suiteql(
                "SELECT id, name FROM subsidiary"
            )
            for sub in subsidiaries:
                resources.append(
                    Resource(
                        id=vektor_id(SOURCE, f"subsidiary:{sub.get('id', '')}"),
                        source=SOURCE,
                        type="netsuite_subsidiary",
                        name=sub.get("name", ""),
                        sensitivity=Sensitivity.HIGH,
                        attributes={"netsuite_id": sub.get("id")},
                    )
                )
        except Exception as exc:
            logger.warning("netsuite.subsidiaries_failed", error=str(exc))

        # 5. Financial modules as resources
        module_resources = self._create_module_resources()
        resources.extend(module_resources)

        logger.info(
            "netsuite.extract.done",
            subjects=len(subjects),
            permissions=len(permissions),
            resources=len(resources),
            assignments=len(assignments),
        )

        return GraphSnapshot(
            source=SOURCE,
            subjects=subjects,
            permissions=permissions,
            resources=resources,
            assignments=assignments,
        )

    # ---- internal: mapping -------------------------------------------------

    def _map_employee(self, emp: dict) -> Subject:
        emp_id = str(emp.get("id", ""))
        is_inactive = emp.get("isinactive", "F")
        inactive = is_inactive in ("T", "True", True, "t")

        first = emp.get("firstname", "")
        last = emp.get("lastname", "")
        display = f"{first} {last}".strip() or emp_id

        supervisor = emp.get("supervisor")
        manager_id = vektor_id(SOURCE, f"emp:{supervisor}") if supervisor else None

        return Subject(
            id=vektor_id(SOURCE, f"emp:{emp_id}"),
            external_id=emp_id,
            source=SOURCE,
            type=SubjectType.HUMAN,
            display_name=display,
            email=emp.get("email"),
            department=str(emp.get("department", "")) if emp.get("department") else None,
            manager_id=manager_id,
            status=SubjectStatus.INACTIVE if inactive else SubjectStatus.ACTIVE,
            attributes={
                "netsuite_id": emp_id,
                "title": emp.get("title"),
                "hire_date": emp.get("hiredate"),
            },
            created_at=utcnow(),
            updated_at=utcnow(),
        )

    def _create_module_resources(self) -> list[Resource]:
        """Create resource objects for NetSuite financial modules."""
        modules = [
            ("AP", "Accounts Payable", Sensitivity.CRITICAL),
            ("AR", "Accounts Receivable", Sensitivity.CRITICAL),
            ("GL", "General Ledger", Sensitivity.CRITICAL),
            ("Payroll", "Payroll", Sensitivity.CRITICAL),
            ("Procurement", "Procurement", Sensitivity.HIGH),
            ("Setup", "System Setup", Sensitivity.CRITICAL),
            ("Reporting", "Financial Reporting", Sensitivity.HIGH),
        ]
        return [
            Resource(
                id=vektor_id(SOURCE, f"module:{code}"),
                source=SOURCE,
                type="netsuite_module",
                name=name,
                sensitivity=sensitivity,
            )
            for code, name, sensitivity in modules
        ]

    # ---- internal: OAuth 1.0a TBA signing ---------------------------------

    def _build_oauth_header(self, method: str, url: str) -> str:
        """Build OAuth 1.0a Authorization header for NetSuite TBA."""
        nonce = uuid.uuid4().hex
        timestamp = str(int(time.time()))

        params = {
            "oauth_consumer_key": self._consumer_key,
            "oauth_nonce": nonce,
            "oauth_signature_method": "HMAC-SHA256",
            "oauth_timestamp": timestamp,
            "oauth_token": self._token_id,
            "oauth_version": "1.0",
        }

        # Build signature base string
        base_params = "&".join(
            f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe='')}"
            for k, v in sorted(params.items())
        )
        base_string = (
            f"{method.upper()}&"
            f"{urllib.parse.quote(url, safe='')}&"
            f"{urllib.parse.quote(base_params, safe='')}"
        )

        # Create signing key
        signing_key = (
            f"{urllib.parse.quote(self._consumer_secret, safe='')}&"
            f"{urllib.parse.quote(self._token_secret, safe='')}"
        )

        # HMAC-SHA256 signature
        signature = b64encode(
            hmac.new(
                signing_key.encode("utf-8"),
                base_string.encode("utf-8"),
                hashlib.sha256,
            ).digest()
        ).decode("utf-8")

        params["oauth_signature"] = signature
        params["realm"] = self._account_id

        header_parts = ", ".join(
            f'{k}="{urllib.parse.quote(v, safe="")}"' for k, v in sorted(params.items())
        )
        return f"OAuth {header_parts}"

    # ---- internal: SuiteQL query engine ------------------------------------

    async def _suiteql(self, query: str, limit: int = 1000) -> list[dict]:
        """Execute a SuiteQL query with pagination."""
        url = f"{self._base_url}/services/rest/query/v1/suiteql"
        all_items: list[dict] = []
        offset = 0

        while True:
            auth_header = self._build_oauth_header("POST", url)
            headers = {
                "Authorization": auth_header,
                "Content-Type": "application/json",
                "Prefer": f"transient, max-results={limit}",
            }
            body = {"q": query + f" OFFSET {offset} FETCH NEXT {limit} ROWS ONLY"}

            try:
                resp = await self._client.post(url, headers=headers, json=body)
                resp.raise_for_status()
                data = resp.json()

                items = data.get("items", [])
                all_items.extend(items)

                if data.get("hasMore", False) and len(items) == limit:
                    offset += limit
                else:
                    break

            except httpx.HTTPStatusError as exc:
                logger.error(
                    "netsuite.suiteql_failed",
                    query=query[:100],
                    status=exc.response.status_code,
                    error=str(exc),
                )
                raise
            except Exception as exc:
                logger.error("netsuite.suiteql_error", query=query[:100], error=str(exc))
                raise

        logger.debug("netsuite.suiteql_done", query=query[:60], rows=len(all_items))
        return all_items
