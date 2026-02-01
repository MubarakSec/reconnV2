"""
Multi-User Support - دعم المستخدمين المتعددين

نظام لإدارة المستخدمين والصلاحيات.

Features:
- إدارة المستخدمين
- الأدوار والصلاحيات
- مشاركة المهام
- سجل النشاط

Example:
    >>> users = UserManager("./users.db")
    >>> user = users.create("admin", "admin@example.com", role=UserRole.ADMIN)
    >>> users.grant_permission(user.id, "jobs:create")
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════
#                     User Types
# ═══════════════════════════════════════════════════════════

class UserRole(Enum):
    """أدوار المستخدمين"""
    ADMIN = "admin"           # كامل الصلاحيات
    MANAGER = "manager"       # إدارة الفريق
    ANALYST = "analyst"       # عرض وتحليل
    OPERATOR = "operator"     # تشغيل المهام
    VIEWER = "viewer"         # عرض فقط


class UserStatus(Enum):
    """حالة المستخدم"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING = "pending"


class Permission(Enum):
    """الصلاحيات"""
    # Jobs
    JOBS_VIEW = "jobs:view"
    JOBS_CREATE = "jobs:create"
    JOBS_EDIT = "jobs:edit"
    JOBS_DELETE = "jobs:delete"
    JOBS_RUN = "jobs:run"
    
    # Results
    RESULTS_VIEW = "results:view"
    RESULTS_EXPORT = "results:export"
    RESULTS_DELETE = "results:delete"
    
    # Assets
    ASSETS_VIEW = "assets:view"
    ASSETS_EDIT = "assets:edit"
    ASSETS_DELETE = "assets:delete"
    
    # Users
    USERS_VIEW = "users:view"
    USERS_CREATE = "users:create"
    USERS_EDIT = "users:edit"
    USERS_DELETE = "users:delete"
    
    # Settings
    SETTINGS_VIEW = "settings:view"
    SETTINGS_EDIT = "settings:edit"
    
    # API
    API_ACCESS = "api:access"
    API_ADMIN = "api:admin"


# Role permissions
ROLE_PERMISSIONS: Dict[UserRole, Set[Permission]] = {
    UserRole.ADMIN: set(Permission),  # All permissions
    
    UserRole.MANAGER: {
        Permission.JOBS_VIEW, Permission.JOBS_CREATE, Permission.JOBS_EDIT,
        Permission.JOBS_RUN, Permission.RESULTS_VIEW, Permission.RESULTS_EXPORT,
        Permission.ASSETS_VIEW, Permission.ASSETS_EDIT,
        Permission.USERS_VIEW, Permission.SETTINGS_VIEW,
        Permission.API_ACCESS,
    },
    
    UserRole.ANALYST: {
        Permission.JOBS_VIEW, Permission.RESULTS_VIEW, Permission.RESULTS_EXPORT,
        Permission.ASSETS_VIEW, Permission.SETTINGS_VIEW,
        Permission.API_ACCESS,
    },
    
    UserRole.OPERATOR: {
        Permission.JOBS_VIEW, Permission.JOBS_CREATE, Permission.JOBS_RUN,
        Permission.RESULTS_VIEW, Permission.ASSETS_VIEW,
        Permission.API_ACCESS,
    },
    
    UserRole.VIEWER: {
        Permission.JOBS_VIEW, Permission.RESULTS_VIEW, Permission.ASSETS_VIEW,
    },
}


@dataclass
class User:
    """مستخدم"""
    
    id: Optional[int] = None
    username: str = ""
    email: str = ""
    password_hash: str = ""
    
    role: UserRole = UserRole.VIEWER
    status: UserStatus = UserStatus.PENDING
    
    # Extra permissions beyond role
    extra_permissions: Set[str] = field(default_factory=set)
    
    # Metadata
    display_name: str = ""
    avatar_url: str = ""
    settings: Dict[str, Any] = field(default_factory=dict)
    
    # Timestamps
    created_at: datetime = field(default_factory=datetime.now)
    last_login: Optional[datetime] = None
    
    def has_permission(self, permission: Permission) -> bool:
        """التحقق من الصلاحية"""
        # Role permissions
        if permission in ROLE_PERMISSIONS.get(self.role, set()):
            return True
        
        # Extra permissions
        return permission.value in self.extra_permissions
    
    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        data = {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role.value,
            "status": self.status.value,
            "display_name": self.display_name or self.username,
            "avatar_url": self.avatar_url,
            "created_at": self.created_at.isoformat(),
            "last_login": self.last_login.isoformat() if self.last_login else None,
        }
        
        if include_sensitive:
            data["extra_permissions"] = list(self.extra_permissions)
            data["settings"] = self.settings
        
        return data


@dataclass
class APIToken:
    """رمز API"""
    
    id: Optional[int] = None
    user_id: int = 0
    token_hash: str = ""
    name: str = ""
    
    scopes: List[str] = field(default_factory=list)
    
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    last_used: Optional[datetime] = None
    
    is_active: bool = True
    
    def is_valid(self) -> bool:
        """التحقق من صلاحية الرمز"""
        if not self.is_active:
            return False
        
        if self.expires_at and datetime.now() > self.expires_at:
            return False
        
        return True


@dataclass
class AuditLog:
    """سجل النشاط"""
    
    id: Optional[int] = None
    user_id: int = 0
    action: str = ""
    resource_type: str = ""
    resource_id: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    ip_address: str = ""
    user_agent: str = ""
    timestamp: datetime = field(default_factory=datetime.now)


# ═══════════════════════════════════════════════════════════
#                     User Manager
# ═══════════════════════════════════════════════════════════

class UserManager:
    """
    إدارة المستخدمين.
    
    Example:
        >>> manager = UserManager("./users.db")
        >>> 
        >>> # إنشاء مستخدم
        >>> user = manager.create(
        ...     username="analyst1",
        ...     email="analyst@example.com",
        ...     password="secure123",
        ...     role=UserRole.ANALYST
        ... )
        >>> 
        >>> # تسجيل الدخول
        >>> session = manager.login("analyst1", "secure123")
        >>> 
        >>> # التحقق من الصلاحية
        >>> if manager.can(user.id, Permission.JOBS_CREATE):
        ...     print("Can create jobs")
    """
    
    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
    
    def _init_db(self) -> None:
        """تهيئة قاعدة البيانات"""
        with self._get_conn() as conn:
            conn.executescript("""
                -- Users table
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT DEFAULT 'viewer',
                    status TEXT DEFAULT 'pending',
                    extra_permissions TEXT DEFAULT '[]',
                    display_name TEXT DEFAULT '',
                    avatar_url TEXT DEFAULT '',
                    settings TEXT DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    last_login TEXT
                );
                
                -- API Tokens table
                CREATE TABLE IF NOT EXISTS api_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    token_hash TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    scopes TEXT DEFAULT '[]',
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    last_used TEXT,
                    is_active INTEGER DEFAULT 1,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                );
                
                -- Sessions table
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    session_token TEXT UNIQUE NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                );
                
                -- Audit logs table
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    resource_type TEXT,
                    resource_id TEXT,
                    details TEXT DEFAULT '{}',
                    ip_address TEXT,
                    user_agent TEXT,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                );
                
                -- Indexes
                CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
                CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
                CREATE INDEX IF NOT EXISTS idx_tokens_user ON api_tokens(user_id);
                CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
                CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token);
                CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id);
                CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
            """)
    
    @contextmanager
    def _get_conn(self) -> Generator[sqlite3.Connection, None, None]:
        """اتصال قاعدة البيانات"""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()
    
    # ─────────────────────────────────────────────────────────
    #                     User CRUD
    # ─────────────────────────────────────────────────────────
    
    def create(
        self,
        username: str,
        email: str,
        password: str,
        role: UserRole = UserRole.VIEWER,
        display_name: str = "",
    ) -> User:
        """إنشاء مستخدم"""
        password_hash = self._hash_password(password)
        now = datetime.now()
        
        with self._get_conn() as conn:
            cursor = conn.execute(
                """
                INSERT INTO users (
                    username, email, password_hash, role, status,
                    display_name, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    username, email, password_hash, role.value,
                    UserStatus.ACTIVE.value, display_name or username,
                    now.isoformat()
                )
            )
            
            user = User(
                id=cursor.lastrowid,
                username=username,
                email=email,
                password_hash=password_hash,
                role=role,
                status=UserStatus.ACTIVE,
                display_name=display_name or username,
                created_at=now,
            )
            
            logger.info("Created user: %s (%s)", username, role.value)
            return user
    
    def get(self, user_id: int) -> Optional[User]:
        """الحصول على مستخدم"""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE id = ?",
                (user_id,)
            ).fetchone()
            
            if row:
                return self._row_to_user(row)
        return None
    
    def get_by_username(self, username: str) -> Optional[User]:
        """الحصول على مستخدم بالاسم"""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,)
            ).fetchone()
            
            if row:
                return self._row_to_user(row)
        return None
    
    def update(self, user: User) -> bool:
        """تحديث مستخدم"""
        if user.id is None:
            return False
        
        with self._get_conn() as conn:
            conn.execute(
                """
                UPDATE users SET
                    email = ?, role = ?, status = ?,
                    extra_permissions = ?, display_name = ?,
                    avatar_url = ?, settings = ?
                WHERE id = ?
                """,
                (
                    user.email, user.role.value, user.status.value,
                    json.dumps(list(user.extra_permissions)),
                    user.display_name, user.avatar_url,
                    json.dumps(user.settings), user.id
                )
            )
            return True
    
    def delete(self, user_id: int) -> bool:
        """حذف مستخدم"""
        with self._get_conn() as conn:
            # Delete related data
            conn.execute("DELETE FROM api_tokens WHERE user_id = ?", (user_id,))
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            
            cursor = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            return cursor.rowcount > 0
    
    def list_users(
        self,
        role: Optional[UserRole] = None,
        status: Optional[UserStatus] = None,
        limit: int = 100,
    ) -> List[User]:
        """قائمة المستخدمين"""
        conditions = []
        params = []
        
        if role:
            conditions.append("role = ?")
            params.append(role.value)
        
        if status:
            conditions.append("status = ?")
            params.append(status.value)
        
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        
        with self._get_conn() as conn:
            rows = conn.execute(
                f"SELECT * FROM users {where} LIMIT ?",
                params + [limit]
            ).fetchall()
            
            return [self._row_to_user(row) for row in rows]
    
    # ─────────────────────────────────────────────────────────
    #                     Authentication
    # ─────────────────────────────────────────────────────────
    
    def login(
        self,
        username: str,
        password: str,
        ip_address: str = "",
        user_agent: str = "",
    ) -> Optional[str]:
        """
        تسجيل الدخول.
        
        Returns:
            Session token or None
        """
        user = self.get_by_username(username)
        
        if not user:
            return None
        
        if user.status != UserStatus.ACTIVE:
            return None
        
        if not self._verify_password(password, user.password_hash):
            return None
        
        # Create session
        session_token = secrets.token_urlsafe(32)
        now = datetime.now()
        expires = now + timedelta(days=7)
        
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO sessions (
                    user_id, session_token, created_at, expires_at,
                    ip_address, user_agent
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    user.id, session_token, now.isoformat(),
                    expires.isoformat(), ip_address, user_agent
                )
            )
            
            # Update last login
            conn.execute(
                "UPDATE users SET last_login = ? WHERE id = ?",
                (now.isoformat(), user.id)
            )
        
        self._log_action(
            user.id, "login", "session", "", 
            {"ip": ip_address}, ip_address, user_agent
        )
        
        return session_token
    
    def logout(self, session_token: str) -> bool:
        """تسجيل الخروج"""
        with self._get_conn() as conn:
            cursor = conn.execute(
                "DELETE FROM sessions WHERE session_token = ?",
                (session_token,)
            )
            return cursor.rowcount > 0
    
    def validate_session(self, session_token: str) -> Optional[User]:
        """التحقق من الجلسة"""
        with self._get_conn() as conn:
            row = conn.execute(
                """
                SELECT u.* FROM users u
                JOIN sessions s ON u.id = s.user_id
                WHERE s.session_token = ? AND s.expires_at > ?
                """,
                (session_token, datetime.now().isoformat())
            ).fetchone()
            
            if row:
                return self._row_to_user(row)
        return None
    
    def change_password(
        self,
        user_id: int,
        old_password: str,
        new_password: str,
    ) -> bool:
        """تغيير كلمة المرور"""
        user = self.get(user_id)
        if not user:
            return False
        
        if not self._verify_password(old_password, user.password_hash):
            return False
        
        new_hash = self._hash_password(new_password)
        
        with self._get_conn() as conn:
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (new_hash, user_id)
            )
            
            # Invalidate all sessions
            conn.execute(
                "DELETE FROM sessions WHERE user_id = ?",
                (user_id,)
            )
        
        return True
    
    # ─────────────────────────────────────────────────────────
    #                     Permissions
    # ─────────────────────────────────────────────────────────
    
    def can(self, user_id: int, permission: Permission) -> bool:
        """التحقق من صلاحية المستخدم"""
        user = self.get(user_id)
        if not user:
            return False
        
        if user.status != UserStatus.ACTIVE:
            return False
        
        return user.has_permission(permission)
    
    def grant_permission(self, user_id: int, permission: Permission) -> bool:
        """منح صلاحية"""
        user = self.get(user_id)
        if not user:
            return False
        
        user.extra_permissions.add(permission.value)
        return self.update(user)
    
    def revoke_permission(self, user_id: int, permission: Permission) -> bool:
        """سحب صلاحية"""
        user = self.get(user_id)
        if not user:
            return False
        
        user.extra_permissions.discard(permission.value)
        return self.update(user)
    
    def set_role(self, user_id: int, role: UserRole) -> bool:
        """تغيير الدور"""
        user = self.get(user_id)
        if not user:
            return False
        
        user.role = role
        return self.update(user)
    
    # ─────────────────────────────────────────────────────────
    #                     API Tokens
    # ─────────────────────────────────────────────────────────
    
    def create_api_token(
        self,
        user_id: int,
        name: str,
        scopes: Optional[List[str]] = None,
        expires_days: Optional[int] = None,
    ) -> Tuple[str, APIToken]:
        """
        إنشاء رمز API.
        
        Returns:
            (raw_token, APIToken)
        """
        raw_token = secrets.token_urlsafe(32)
        token_hash = self._hash_token(raw_token)
        now = datetime.now()
        
        expires = None
        if expires_days:
            expires = now + timedelta(days=expires_days)
        
        with self._get_conn() as conn:
            cursor = conn.execute(
                """
                INSERT INTO api_tokens (
                    user_id, token_hash, name, scopes,
                    created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id, token_hash, name, json.dumps(scopes or []),
                    now.isoformat(), expires.isoformat() if expires else None
                )
            )
            
            token = APIToken(
                id=cursor.lastrowid,
                user_id=user_id,
                token_hash=token_hash,
                name=name,
                scopes=scopes or [],
                created_at=now,
                expires_at=expires,
            )
        
        return raw_token, token
    
    def validate_api_token(self, raw_token: str) -> Optional[Tuple[User, APIToken]]:
        """التحقق من رمز API"""
        token_hash = self._hash_token(raw_token)
        
        with self._get_conn() as conn:
            row = conn.execute(
                """
                SELECT t.*, u.* FROM api_tokens t
                JOIN users u ON t.user_id = u.id
                WHERE t.token_hash = ? AND t.is_active = 1
                """,
                (token_hash,)
            ).fetchone()
            
            if not row:
                return None
            
            # Check expiration
            if row["expires_at"]:
                expires = datetime.fromisoformat(row["expires_at"])
                if datetime.now() > expires:
                    return None
            
            # Update last used
            conn.execute(
                "UPDATE api_tokens SET last_used = ? WHERE id = ?",
                (datetime.now().isoformat(), row["id"])
            )
            
            user = self._row_to_user(row)
            token = APIToken(
                id=row["id"],
                user_id=row["user_id"],
                token_hash=row["token_hash"],
                name=row["name"],
                scopes=json.loads(row["scopes"]),
                created_at=datetime.fromisoformat(row["created_at"]),
                expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
                last_used=datetime.now(),
            )
            
            return user, token
    
    def revoke_api_token(self, token_id: int) -> bool:
        """إلغاء رمز API"""
        with self._get_conn() as conn:
            cursor = conn.execute(
                "UPDATE api_tokens SET is_active = 0 WHERE id = ?",
                (token_id,)
            )
            return cursor.rowcount > 0
    
    def list_api_tokens(self, user_id: int) -> List[APIToken]:
        """قائمة رموز API"""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM api_tokens WHERE user_id = ? AND is_active = 1",
                (user_id,)
            ).fetchall()
            
            return [
                APIToken(
                    id=row["id"],
                    user_id=row["user_id"],
                    token_hash=row["token_hash"],
                    name=row["name"],
                    scopes=json.loads(row["scopes"]),
                    created_at=datetime.fromisoformat(row["created_at"]),
                    expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
                    last_used=datetime.fromisoformat(row["last_used"]) if row["last_used"] else None,
                    is_active=bool(row["is_active"]),
                )
                for row in rows
            ]
    
    # ─────────────────────────────────────────────────────────
    #                     Audit Logging
    # ─────────────────────────────────────────────────────────
    
    def _log_action(
        self,
        user_id: int,
        action: str,
        resource_type: str = "",
        resource_id: str = "",
        details: Optional[Dict] = None,
        ip_address: str = "",
        user_agent: str = "",
    ) -> None:
        """تسجيل النشاط"""
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO audit_logs (
                    user_id, action, resource_type, resource_id,
                    details, ip_address, user_agent, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id, action, resource_type, resource_id,
                    json.dumps(details or {}), ip_address, user_agent,
                    datetime.now().isoformat()
                )
            )
    
    def log_action(
        self,
        user_id: int,
        action: str,
        resource_type: str = "",
        resource_id: str = "",
        details: Optional[Dict] = None,
    ) -> None:
        """تسجيل نشاط (API عام)"""
        self._log_action(user_id, action, resource_type, resource_id, details)
    
    def get_audit_logs(
        self,
        user_id: Optional[int] = None,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
        since: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[AuditLog]:
        """الحصول على سجل النشاط"""
        conditions = []
        params = []
        
        if user_id:
            conditions.append("user_id = ?")
            params.append(user_id)
        
        if action:
            conditions.append("action = ?")
            params.append(action)
        
        if resource_type:
            conditions.append("resource_type = ?")
            params.append(resource_type)
        
        if since:
            conditions.append("timestamp >= ?")
            params.append(since.isoformat())
        
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        
        with self._get_conn() as conn:
            rows = conn.execute(
                f"""
                SELECT * FROM audit_logs
                {where}
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                params + [limit]
            ).fetchall()
            
            return [
                AuditLog(
                    id=row["id"],
                    user_id=row["user_id"],
                    action=row["action"],
                    resource_type=row["resource_type"],
                    resource_id=row["resource_id"],
                    details=json.loads(row["details"]),
                    ip_address=row["ip_address"],
                    user_agent=row["user_agent"],
                    timestamp=datetime.fromisoformat(row["timestamp"]),
                )
                for row in rows
            ]
    
    # ─────────────────────────────────────────────────────────
    #                     Helpers
    # ─────────────────────────────────────────────────────────
    
    def _hash_password(self, password: str) -> str:
        """تشفير كلمة المرور"""
        # Use PBKDF2 with SHA256
        import hashlib
        salt = secrets.token_hex(16)
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt.encode(), 100000
        )
        return f"{salt}:{dk.hex()}"
    
    def _verify_password(self, password: str, password_hash: str) -> bool:
        """التحقق من كلمة المرور"""
        try:
            salt, stored_hash = password_hash.split(":")
            dk = hashlib.pbkdf2_hmac(
                "sha256", password.encode(), salt.encode(), 100000
            )
            return dk.hex() == stored_hash
        except Exception:
            return False
    
    def _hash_token(self, token: str) -> str:
        """تشفير الرمز"""
        return hashlib.sha256(token.encode()).hexdigest()
    
    def _row_to_user(self, row: sqlite3.Row) -> User:
        """تحويل صف إلى مستخدم"""
        return User(
            id=row["id"],
            username=row["username"],
            email=row["email"],
            password_hash=row["password_hash"],
            role=UserRole(row["role"]),
            status=UserStatus(row["status"]),
            extra_permissions=set(json.loads(row["extra_permissions"])),
            display_name=row["display_name"],
            avatar_url=row["avatar_url"],
            settings=json.loads(row["settings"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            last_login=datetime.fromisoformat(row["last_login"]) if row["last_login"] else None,
        )


# ═══════════════════════════════════════════════════════════
#                     Job Sharing
# ═══════════════════════════════════════════════════════════

class ShareLevel(Enum):
    """مستوى المشاركة"""
    PRIVATE = "private"     # المالك فقط
    TEAM = "team"           # الفريق
    ORGANIZATION = "org"    # المؤسسة
    PUBLIC = "public"       # عام


@dataclass 
class SharedResource:
    """مورد مشترك"""
    
    id: Optional[int] = None
    resource_type: str = ""
    resource_id: str = ""
    owner_id: int = 0
    
    share_level: ShareLevel = ShareLevel.PRIVATE
    shared_with: List[int] = field(default_factory=list)  # User IDs
    
    # Permissions
    can_view: bool = True
    can_edit: bool = False
    can_delete: bool = False
    can_share: bool = False
    
    created_at: datetime = field(default_factory=datetime.now)
    
    def can_access(self, user_id: int) -> bool:
        """هل يمكن للمستخدم الوصول"""
        if user_id == self.owner_id:
            return True
        
        if self.share_level == ShareLevel.PUBLIC:
            return True
        
        if user_id in self.shared_with:
            return True
        
        return False


class SharingManager:
    """
    إدارة المشاركة.
    
    Example:
        >>> sharing = SharingManager(user_manager)
        >>> 
        >>> # مشاركة مهمة
        >>> sharing.share(
        ...     owner_id=1,
        ...     resource_type="job",
        ...     resource_id="job-123",
        ...     share_with=[2, 3],
        ...     can_edit=True
        ... )
        >>> 
        >>> # التحقق من الوصول
        >>> if sharing.can_access(user_id=2, resource_type="job", resource_id="job-123"):
        ...     print("Access granted")
    """
    
    def __init__(self, user_manager: UserManager):
        self.users = user_manager
        self._shares: Dict[str, SharedResource] = {}
    
    def share(
        self,
        owner_id: int,
        resource_type: str,
        resource_id: str,
        share_with: List[int],
        can_view: bool = True,
        can_edit: bool = False,
        can_delete: bool = False,
    ) -> SharedResource:
        """مشاركة مورد"""
        key = f"{resource_type}:{resource_id}"
        
        shared = SharedResource(
            resource_type=resource_type,
            resource_id=resource_id,
            owner_id=owner_id,
            share_level=ShareLevel.PRIVATE,
            shared_with=share_with,
            can_view=can_view,
            can_edit=can_edit,
            can_delete=can_delete,
        )
        
        self._shares[key] = shared
        
        # Log
        self.users.log_action(
            owner_id, "share", resource_type, resource_id,
            {"shared_with": share_with}
        )
        
        return shared
    
    def unshare(
        self,
        resource_type: str,
        resource_id: str,
        user_id: int,
    ) -> bool:
        """إلغاء المشاركة"""
        key = f"{resource_type}:{resource_id}"
        
        if key in self._shares:
            shared = self._shares[key]
            if user_id in shared.shared_with:
                shared.shared_with.remove(user_id)
                return True
        
        return False
    
    def set_public(
        self,
        resource_type: str,
        resource_id: str,
        owner_id: int,
    ) -> bool:
        """جعل المورد عام"""
        key = f"{resource_type}:{resource_id}"
        
        if key not in self._shares:
            self._shares[key] = SharedResource(
                resource_type=resource_type,
                resource_id=resource_id,
                owner_id=owner_id,
            )
        
        self._shares[key].share_level = ShareLevel.PUBLIC
        return True
    
    def can_access(
        self,
        user_id: int,
        resource_type: str,
        resource_id: str,
    ) -> bool:
        """التحقق من الوصول"""
        key = f"{resource_type}:{resource_id}"
        
        if key not in self._shares:
            return False
        
        return self._shares[key].can_access(user_id)
    
    def get_shared_with_me(
        self,
        user_id: int,
        resource_type: Optional[str] = None,
    ) -> List[SharedResource]:
        """الموارد المشاركة معي"""
        results = []
        
        for shared in self._shares.values():
            if resource_type and shared.resource_type != resource_type:
                continue
            
            if user_id in shared.shared_with:
                results.append(shared)
        
        return results
    
    def get_my_shares(
        self,
        owner_id: int,
        resource_type: Optional[str] = None,
    ) -> List[SharedResource]:
        """مشاركاتي"""
        results = []
        
        for shared in self._shares.values():
            if resource_type and shared.resource_type != resource_type:
                continue
            
            if shared.owner_id == owner_id:
                results.append(shared)
        
        return results
