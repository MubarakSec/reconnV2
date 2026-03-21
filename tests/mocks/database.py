"""
Database Mocks - Mocks لقواعد البيانات

للاختبار بدون قاعدة بيانات حقيقية
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


# ═══════════════════════════════════════════════════════════
#                     Mock Database
# ═══════════════════════════════════════════════════════════


@dataclass
class MockDatabase:
    """Mock لقاعدة البيانات"""

    tables: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)

    def __post_init__(self):
        self.tables = {
            "jobs": [],
            "results": [],
            "assets": [],
            "users": [],
            "api_keys": [],
        }

    # ─────────────────────────────────────────────────────────
    #                     CRUD Operations
    # ─────────────────────────────────────────────────────────

    def insert(self, table: str, data: Dict[str, Any]) -> int:
        """إدراج صف"""
        if table not in self.tables:
            self.tables[table] = []

        data = data.copy()
        data["id"] = len(self.tables[table]) + 1
        data["created_at"] = datetime.now().isoformat()
        self.tables[table].append(data)

        return data["id"]

    def select(
        self,
        table: str,
        where: Optional[Dict[str, Any]] = None,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """استعلام"""
        if table not in self.tables:
            return []

        rows = self.tables[table]

        if where:
            rows = [r for r in rows if all(r.get(k) == v for k, v in where.items())]

        if limit:
            rows = rows[:limit]

        return rows

    def select_one(
        self,
        table: str,
        where: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """استعلام لصف واحد"""
        rows = self.select(table, where, limit=1)
        return rows[0] if rows else None

    def update(
        self,
        table: str,
        data: Dict[str, Any],
        where: Dict[str, Any],
    ) -> int:
        """تحديث"""
        if table not in self.tables:
            return 0

        count = 0
        for row in self.tables[table]:
            if all(row.get(k) == v for k, v in where.items()):
                row.update(data)
                row["updated_at"] = datetime.now().isoformat()
                count += 1

        return count

    def delete(self, table: str, where: Dict[str, Any]) -> int:
        """حذف"""
        if table not in self.tables:
            return 0

        original = len(self.tables[table])
        self.tables[table] = [
            r
            for r in self.tables[table]
            if not all(r.get(k) == v for k, v in where.items())
        ]

        return original - len(self.tables[table])

    def count(self, table: str, where: Optional[Dict[str, Any]] = None) -> int:
        """عدد الصفوف"""
        return len(self.select(table, where))

    # ─────────────────────────────────────────────────────────
    #                     Utilities
    # ─────────────────────────────────────────────────────────

    def clear(self, table: Optional[str] = None) -> None:
        """مسح البيانات"""
        if table:
            self.tables[table] = []
        else:
            for t in self.tables:
                self.tables[t] = []

    def seed(self, table: str, data: List[Dict[str, Any]]) -> None:
        """تعبئة بيانات"""
        for row in data:
            self.insert(table, row)


# ═══════════════════════════════════════════════════════════
#                     Mock Inventory
# ═══════════════════════════════════════════════════════════


class MockInventory:
    """Mock لـ AssetInventory"""

    def __init__(self):
        self.db = MockDatabase()
        self.db.tables["assets"] = []
        self.db.tables["scans"] = []

    # ─────────────────────────────────────────────────────────
    #                     Assets
    # ─────────────────────────────────────────────────────────

    def add_asset(
        self,
        asset_type: str,
        value: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> int:
        """إضافة asset"""
        return self.db.insert(
            "assets",
            {
                "type": asset_type,
                "value": value,
                "metadata": json.dumps(metadata or {}),
                "status": "active",
            },
        )

    def get_asset(self, asset_id: int) -> Optional[Dict[str, Any]]:
        """الحصول على asset"""
        asset = self.db.select_one("assets", {"id": asset_id})
        if asset and "metadata" in asset:
            asset["metadata"] = json.loads(asset["metadata"])
        return asset

    def search_assets(
        self,
        asset_type: Optional[str] = None,
        query: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """البحث عن assets"""
        where = {}
        if asset_type:
            where["type"] = asset_type

        assets = self.db.select("assets", where)

        if query:
            assets = [a for a in assets if query.lower() in a["value"].lower()]

        return assets

    def update_asset(self, asset_id: int, data: Dict[str, Any]) -> bool:
        """تحديث asset"""
        if "metadata" in data and isinstance(data["metadata"], dict):
            data["metadata"] = json.dumps(data["metadata"])
        return self.db.update("assets", data, {"id": asset_id}) > 0

    def delete_asset(self, asset_id: int) -> bool:
        """حذف asset"""
        return self.db.delete("assets", {"id": asset_id}) > 0

    # ─────────────────────────────────────────────────────────
    #                     Scans
    # ─────────────────────────────────────────────────────────

    def record_scan(
        self,
        asset_id: int,
        scan_type: str,
        results: Dict[str, Any],
    ) -> int:
        """تسجيل scan"""
        return self.db.insert(
            "scans",
            {
                "asset_id": asset_id,
                "scan_type": scan_type,
                "results": json.dumps(results),
                "status": "completed",
            },
        )

    def get_scans(self, asset_id: int) -> List[Dict[str, Any]]:
        """الحصول على scans"""
        scans = self.db.select("scans", {"asset_id": asset_id})
        for scan in scans:
            if "results" in scan:
                scan["results"] = json.loads(scan["results"])
        return scans

    # ─────────────────────────────────────────────────────────
    #                     Stats
    # ─────────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        """الحصول على الإحصائيات"""
        return {
            "total_assets": self.db.count("assets"),
            "total_scans": self.db.count("scans"),
            "by_type": self._count_by_type(),
        }

    def _count_by_type(self) -> Dict[str, int]:
        """عد حسب النوع"""
        counts = {}
        for asset in self.db.tables.get("assets", []):
            t = asset.get("type", "unknown")
            counts[t] = counts.get(t, 0) + 1
        return counts


# ═══════════════════════════════════════════════════════════
#                     Mock User Manager
# ═══════════════════════════════════════════════════════════


class MockUserManager:
    """Mock لـ UserManager"""

    def __init__(self):
        self.db = MockDatabase()
        self._current_user = None

    # ─────────────────────────────────────────────────────────
    #                     Users
    # ─────────────────────────────────────────────────────────

    def create_user(
        self,
        username: str,
        email: str,
        password: str,
        role: str = "user",
    ) -> int:
        """إنشاء مستخدم"""
        return self.db.insert(
            "users",
            {
                "username": username,
                "email": email,
                "password_hash": f"hashed_{password}",
                "role": role,
                "active": True,
            },
        )

    def get_user(self, user_id: int) -> Optional[Dict[str, Any]]:
        """الحصول على مستخدم"""
        return self.db.select_one("users", {"id": user_id})

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """الحصول على مستخدم بالاسم"""
        return self.db.select_one("users", {"username": username})

    def authenticate(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """المصادقة"""
        user = self.get_user_by_username(username)
        if user and user.get("password_hash") == f"hashed_{password}":
            if user.get("active", True):
                self._current_user = user
                return user
        return None

    def update_user(self, user_id: int, data: Dict[str, Any]) -> bool:
        """تحديث مستخدم"""
        if "password" in data:
            data["password_hash"] = f"hashed_{data.pop('password')}"
        return self.db.update("users", data, {"id": user_id}) > 0

    def delete_user(self, user_id: int) -> bool:
        """حذف مستخدم"""
        return self.db.delete("users", {"id": user_id}) > 0

    # ─────────────────────────────────────────────────────────
    #                     API Keys
    # ─────────────────────────────────────────────────────────

    def create_api_key(
        self,
        user_id: int,
        name: str,
        permissions: Optional[List[str]] = None,
    ) -> str:
        """إنشاء API key"""
        key = f"rk_test_{user_id}_{len(self.db.tables['api_keys'])}"

        self.db.insert(
            "api_keys",
            {
                "user_id": user_id,
                "name": name,
                "key_hash": f"hashed_{key}",
                "permissions": json.dumps(permissions or ["read"]),
                "active": True,
            },
        )

        return key

    def validate_api_key(self, key: str) -> Optional[Dict[str, Any]]:
        """التحقق من API key"""
        key_data = self.db.select_one("api_keys", {"key_hash": f"hashed_{key}"})
        if key_data and key_data.get("active"):
            key_data["permissions"] = json.loads(key_data.get("permissions", "[]"))
            return key_data
        return None

    def revoke_api_key(self, key_id: int) -> bool:
        """إلغاء API key"""
        return self.db.update("api_keys", {"active": False}, {"id": key_id}) > 0

    # ─────────────────────────────────────────────────────────
    #                     Permissions
    # ─────────────────────────────────────────────────────────

    def has_permission(self, user_id: int, permission: str) -> bool:
        """التحقق من صلاحية"""
        user = self.get_user(user_id)
        if not user:
            return False

        role = user.get("role", "user")

        # Admin has all permissions
        if role == "admin":
            return True

        # Define role permissions
        role_permissions = {
            "user": ["read", "create_job"],
            "analyst": ["read", "create_job", "view_results"],
            "admin": ["*"],
        }

        return permission in role_permissions.get(role, [])

    @property
    def current_user(self) -> Optional[Dict[str, Any]]:
        return self._current_user

    def logout(self) -> None:
        self._current_user = None


# ═══════════════════════════════════════════════════════════
#                     Factory Functions
# ═══════════════════════════════════════════════════════════


def create_mock_db() -> MockDatabase:
    """إنشاء mock database"""
    return MockDatabase()


def create_mock_inventory() -> MockInventory:
    """إنشاء mock inventory"""
    return MockInventory()


def create_mock_user_manager() -> MockUserManager:
    """إنشاء mock user manager"""
    return MockUserManager()


def create_seeded_inventory() -> MockInventory:
    """إنشاء inventory مع بيانات"""
    inventory = MockInventory()

    # Add sample assets
    inventory.add_asset("domain", "example.com", {"registrar": "test"})
    inventory.add_asset("subdomain", "api.example.com", {"source": "subfinder"})
    inventory.add_asset("ip", "192.168.1.1", {"ports": [80, 443]})

    return inventory


def create_seeded_user_manager() -> MockUserManager:
    """إنشاء user manager مع بيانات"""
    manager = MockUserManager()

    # Add sample users
    manager.create_user("admin", "admin@example.com", "admin123", "admin")
    manager.create_user("user", "user@example.com", "user123", "user")
    manager.create_user("analyst", "analyst@example.com", "analyst123", "analyst")

    return manager
