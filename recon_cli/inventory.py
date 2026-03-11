"""
Asset Inventory - جرد الأصول

نظام لتتبع وإدارة الأصول المكتشفة.

Features:
- تخزين الأصول
- التصنيف التلقائي
- العلاقات بين الأصول
- التصدير والاستيراد

Example:
    >>> inventory = AssetInventory("./inventory.db")
    >>> inventory.add_asset(domain="example.com", type="domain")
    >>> inventory.add_asset(ip="1.2.3.4", domain="example.com")
    >>> assets = inventory.search(type="domain")
"""

from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════
#                     Asset Types
# ═══════════════════════════════════════════════════════════

class AssetType(Enum):
    """أنواع الأصول"""
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    PORT = "port"
    ENDPOINT = "endpoint"
    TECHNOLOGY = "technology"
    CERTIFICATE = "certificate"
    EMAIL = "email"
    CREDENTIAL = "credential"
    VULNERABILITY = "vulnerability"
    SECRET = "secret"
    OTHER = "other"


class AssetStatus(Enum):
    """حالة الأصل"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    UNKNOWN = "unknown"
    DEPRECATED = "deprecated"


class RiskLevel(Enum):
    """مستوى الخطورة"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Asset:
    """أصل واحد"""
    
    id: Optional[int] = None
    type: AssetType = AssetType.OTHER
    value: str = ""
    
    # Metadata
    status: AssetStatus = AssetStatus.UNKNOWN
    risk_level: RiskLevel = RiskLevel.INFO
    confidence: float = 1.0  # 0-1
    
    # Discovery
    source: str = ""
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    
    # Relations
    parent_id: Optional[int] = None
    
    # Extra data
    attributes: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "value": self.value,
            "status": self.status.value,
            "risk_level": self.risk_level.value,
            "confidence": self.confidence,
            "source": self.source,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "parent_id": self.parent_id,
            "attributes": self.attributes,
            "tags": self.tags,
            "notes": self.notes,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Asset":
        data = data.copy()
        data["type"] = AssetType(data["type"])
        data["status"] = AssetStatus(data["status"])
        data["risk_level"] = RiskLevel(data["risk_level"])
        data["first_seen"] = datetime.fromisoformat(data["first_seen"])
        data["last_seen"] = datetime.fromisoformat(data["last_seen"])
        return cls(**data)


@dataclass
class AssetRelation:
    """علاقة بين أصلين"""
    
    id: Optional[int] = None
    source_id: int = 0
    target_id: int = 0
    relation_type: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    attributes: Dict[str, Any] = field(default_factory=dict)


# ═══════════════════════════════════════════════════════════
#                     Asset Inventory
# ═══════════════════════════════════════════════════════════

class AssetInventory:
    """
    جرد الأصول.
    
    Example:
        >>> inventory = AssetInventory("./inventory.db")
        >>> 
        >>> # إضافة أصول
        >>> domain = inventory.add(
        ...     type=AssetType.DOMAIN,
        ...     value="example.com",
        ...     source="manual"
        ... )
        >>> 
        >>> subdomain = inventory.add(
        ...     type=AssetType.SUBDOMAIN,
        ...     value="api.example.com",
        ...     parent_id=domain.id
        ... )
        >>> 
        >>> # البحث
        >>> results = inventory.search(type=AssetType.SUBDOMAIN)
        >>> 
        >>> # التصدير
        >>> inventory.export("assets.json")
    """
    
    def __init__(self, db_path: Union[str, Path]):
        """
        Args:
            db_path: مسار قاعدة البيانات
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        self._init_db()
    
    def _init_db(self) -> None:
        """تهيئة قاعدة البيانات"""
        with self._get_conn() as conn:
            conn.executescript("""
                -- Assets table
                CREATE TABLE IF NOT EXISTS assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    status TEXT DEFAULT 'unknown',
                    risk_level TEXT DEFAULT 'info',
                    confidence REAL DEFAULT 1.0,
                    source TEXT DEFAULT '',
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    parent_id INTEGER,
                    attributes TEXT DEFAULT '{}',
                    tags TEXT DEFAULT '[]',
                    notes TEXT DEFAULT '',
                    UNIQUE(type, value)
                );
                
                -- Relations table
                CREATE TABLE IF NOT EXISTS relations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_id INTEGER NOT NULL,
                    target_id INTEGER NOT NULL,
                    relation_type TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    attributes TEXT DEFAULT '{}',
                    FOREIGN KEY (source_id) REFERENCES assets(id),
                    FOREIGN KEY (target_id) REFERENCES assets(id),
                    UNIQUE(source_id, target_id, relation_type)
                );
                
                -- Indexes
                CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(type);
                CREATE INDEX IF NOT EXISTS idx_assets_value ON assets(value);
                CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(status);
                CREATE INDEX IF NOT EXISTS idx_assets_risk ON assets(risk_level);
                CREATE INDEX IF NOT EXISTS idx_assets_parent ON assets(parent_id);
                CREATE INDEX IF NOT EXISTS idx_relations_source ON relations(source_id);
                CREATE INDEX IF NOT EXISTS idx_relations_target ON relations(target_id);
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
    #                     CRUD Operations
    # ─────────────────────────────────────────────────────────
    
    def add(
        self,
        type: AssetType,
        value: str,
        status: AssetStatus = AssetStatus.UNKNOWN,
        risk_level: RiskLevel = RiskLevel.INFO,
        confidence: float = 1.0,
        source: str = "",
        parent_id: Optional[int] = None,
        attributes: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
        notes: str = "",
    ) -> Asset:
        """
        إضافة أصل جديد.
        
        إذا كان الأصل موجوداً، يتم تحديث last_seen.
        """
        now = datetime.now()
        
        with self._get_conn() as conn:
            # Check if exists
            existing = conn.execute(
                "SELECT * FROM assets WHERE type = ? AND value = ?",
                (type.value, value)
            ).fetchone()
            
            if existing:
                # Update last_seen
                conn.execute(
                    "UPDATE assets SET last_seen = ? WHERE id = ?",
                    (now.isoformat(), existing["id"])
                )
                return self._row_to_asset(existing)
            
            # Insert new
            cursor = conn.execute(
                """
                INSERT INTO assets (
                    type, value, status, risk_level, confidence,
                    source, first_seen, last_seen, parent_id,
                    attributes, tags, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    type.value, value, status.value, risk_level.value,
                    confidence, source, now.isoformat(), now.isoformat(),
                    parent_id, json.dumps(attributes or {}),
                    json.dumps(tags or []), notes
                )
            )
            
            asset = Asset(
                id=cursor.lastrowid,
                type=type,
                value=value,
                status=status,
                risk_level=risk_level,
                confidence=confidence,
                source=source,
                first_seen=now,
                last_seen=now,
                parent_id=parent_id,
                attributes=attributes or {},
                tags=tags or [],
                notes=notes,
            )
            
            logger.debug("Added asset: %s (%s)", value, type.value)
            return asset
    
    def get(self, asset_id: int) -> Optional[Asset]:
        """الحصول على أصل"""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM assets WHERE id = ?",
                (asset_id,)
            ).fetchone()
            
            if row:
                return self._row_to_asset(row)
        return None
    
    def update(self, asset: Asset) -> bool:
        """تحديث أصل"""
        if asset.id is None:
            return False
        
        with self._get_conn() as conn:
            conn.execute(
                """
                UPDATE assets SET
                    type = ?, value = ?, status = ?, risk_level = ?,
                    confidence = ?, source = ?, last_seen = ?,
                    parent_id = ?, attributes = ?, tags = ?, notes = ?
                WHERE id = ?
                """,
                (
                    asset.type.value, asset.value, asset.status.value,
                    asset.risk_level.value, asset.confidence, asset.source,
                    datetime.now().isoformat(), asset.parent_id,
                    json.dumps(asset.attributes), json.dumps(asset.tags),
                    asset.notes, asset.id
                )
            )
            return True
    
    def delete(self, asset_id: int) -> bool:
        """حذف أصل"""
        with self._get_conn() as conn:
            # Delete relations
            conn.execute(
                "DELETE FROM relations WHERE source_id = ? OR target_id = ?",
                (asset_id, asset_id)
            )
            
            # Delete asset
            cursor = conn.execute(
                "DELETE FROM assets WHERE id = ?",
                (asset_id,)
            )
            return cursor.rowcount > 0
    
    # ─────────────────────────────────────────────────────────
    #                     Search
    # ─────────────────────────────────────────────────────────
    
    def search(
        self,
        type: Optional[AssetType] = None,
        value_contains: Optional[str] = None,
        status: Optional[AssetStatus] = None,
        risk_level: Optional[RiskLevel] = None,
        source: Optional[str] = None,
        parent_id: Optional[int] = None,
        tag: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Asset]:
        """
        بحث في الأصول.
        
        Args:
            type: نوع الأصل
            value_contains: قيمة تحتوي على
            status: الحالة
            risk_level: مستوى الخطورة
            source: المصدر
            parent_id: معرف الأب
            tag: وسم
            limit: الحد الأقصى
            offset: البداية
        """
        conditions = []
        params = []
        
        if type:
            conditions.append("type = ?")
            params.append(type.value)
        
        if value_contains:
            conditions.append("value LIKE ?")
            params.append(f"%{value_contains}%")
        
        if status:
            conditions.append("status = ?")
            params.append(status.value)
        
        if risk_level:
            conditions.append("risk_level = ?")
            params.append(risk_level.value)
        
        if source:
            conditions.append("source = ?")
            params.append(source)
        
        if parent_id is not None:
            conditions.append("parent_id = ?")
            params.append(parent_id)
        
        if tag:
            conditions.append("tags LIKE ?")
            params.append(f'%"{tag}"%')
        
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        
        query = f"""
            SELECT * FROM assets
            {where}
            ORDER BY last_seen DESC
            LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])
        
        with self._get_conn() as conn:
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_asset(row) for row in rows]
    
    def find_by_value(self, value: str) -> Optional[Asset]:
        """البحث بالقيمة"""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM assets WHERE value = ?",
                (value,)
            ).fetchone()
            
            if row:
                return self._row_to_asset(row)
        return None
    
    def count(
        self,
        type: Optional[AssetType] = None,
        status: Optional[AssetStatus] = None,
    ) -> int:
        """عدد الأصول"""
        conditions = []
        params = []
        
        if type:
            conditions.append("type = ?")
            params.append(type.value)
        
        if status:
            conditions.append("status = ?")
            params.append(status.value)
        
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        
        with self._get_conn() as conn:
            row = conn.execute(
                f"SELECT COUNT(*) as cnt FROM assets {where}",
                params
            ).fetchone()
            return row["cnt"]
    
    # ─────────────────────────────────────────────────────────
    #                     Relations
    # ─────────────────────────────────────────────────────────
    
    def add_relation(
        self,
        source_id: int,
        target_id: int,
        relation_type: str,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> Optional[AssetRelation]:
        """إضافة علاقة"""
        now = datetime.now()
        
        with self._get_conn() as conn:
            try:
                cursor = conn.execute(
                    """
                    INSERT INTO relations (
                        source_id, target_id, relation_type, created_at, attributes
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        source_id, target_id, relation_type,
                        now.isoformat(), json.dumps(attributes or {})
                    )
                )
                
                return AssetRelation(
                    id=cursor.lastrowid,
                    source_id=source_id,
                    target_id=target_id,
                    relation_type=relation_type,
                    created_at=now,
                    attributes=attributes or {},
                )
            except sqlite3.IntegrityError:
                return None
    
    def get_relations(
        self,
        asset_id: int,
        direction: str = "both",
    ) -> List[Tuple[AssetRelation, Asset]]:
        """
        الحصول على علاقات أصل.
        
        Args:
            asset_id: معرف الأصل
            direction: both, outgoing, incoming
        """
        results = []
        
        with self._get_conn() as conn:
            if direction in ("both", "outgoing"):
                rows = conn.execute(
                    """
                    SELECT r.*, a.* FROM relations r
                    JOIN assets a ON r.target_id = a.id
                    WHERE r.source_id = ?
                    """,
                    (asset_id,)
                ).fetchall()
                
                for row in rows:
                    relation = AssetRelation(
                        id=row["id"],
                        source_id=row["source_id"],
                        target_id=row["target_id"],
                        relation_type=row["relation_type"],
                        created_at=datetime.fromisoformat(row["created_at"]),
                        attributes=json.loads(row["attributes"]),
                    )
                    asset = self._row_to_asset(row)
                    results.append((relation, asset))
            
            if direction in ("both", "incoming"):
                rows = conn.execute(
                    """
                    SELECT r.*, a.* FROM relations r
                    JOIN assets a ON r.source_id = a.id
                    WHERE r.target_id = ?
                    """,
                    (asset_id,)
                ).fetchall()
                
                for row in rows:
                    relation = AssetRelation(
                        id=row["id"],
                        source_id=row["source_id"],
                        target_id=row["target_id"],
                        relation_type=row["relation_type"],
                        created_at=datetime.fromisoformat(row["created_at"]),
                        attributes=json.loads(row["attributes"]),
                    )
                    asset = self._row_to_asset(row)
                    results.append((relation, asset))
        
        return results
    
    def get_children(self, parent_id: int) -> List[Asset]:
        """الحصول على الأبناء"""
        return self.search(parent_id=parent_id)
    
    def get_tree(self, root_id: int, max_depth: int = 5) -> Dict[str, Any]:
        """
        شجرة الأصول.
        
        Returns:
            {"asset": Asset, "children": [subtrees]}
        """
        asset = self.get(root_id)
        if not asset:
            return {}
        
        tree = {
            "asset": asset.to_dict(),
            "children": [],
        }
        
        if max_depth > 0:
            children = self.get_children(root_id)
            for child in children:
                if child.id:
                    subtree = self.get_tree(child.id, max_depth - 1)
                    if subtree:
                        tree["children"].append(subtree)
        
        return tree
    
    # ─────────────────────────────────────────────────────────
    #                     Bulk Operations
    # ─────────────────────────────────────────────────────────
    
    def bulk_add(self, assets: List[Dict[str, Any]]) -> int:
        """إضافة أصول بالجملة"""
        added = 0
        
        for asset_data in assets:
            try:
                asset_type = AssetType(asset_data.get("type", "other"))
                value = asset_data.get("value", "")
                
                if value:
                    self.add(
                        type=asset_type,
                        value=value,
                        source=asset_data.get("source", "bulk"),
                        attributes=asset_data.get("attributes", {}),
                        tags=asset_data.get("tags", []),
                    )
                    added += 1
            except Exception as e:
                logger.warning("Failed to add asset: %s", e)
        
        return added
    
    def import_from_scan(
        self,
        results: List[Dict[str, Any]],
        source: str = "scan",
    ) -> Dict[str, int]:
        """
        استيراد من نتائج الفحص.
        
        يكتشف تلقائياً نوع كل نتيجة ويضيفها.
        """
        stats = {
            "total": len(results),
            "imported": 0,
            "skipped": 0,
        }
        
        for result in results:
            try:
                asset = self._result_to_asset(result, source)
                if asset:
                    self.add(**asset)
                    stats["imported"] += 1
                else:
                    stats["skipped"] += 1
            except Exception as e:
                logger.warning("Import error: %s", e)
                stats["skipped"] += 1
        
        return stats
    
    def _result_to_asset(
        self,
        result: Dict[str, Any],
        source: str,
    ) -> Optional[Dict[str, Any]]:
        """تحويل نتيجة إلى أصل"""
        # Detect type
        if "subdomain" in result or "host" in result:
            value = result.get("subdomain") or result.get("host")
            if "." in value:
                return {
                    "type": AssetType.SUBDOMAIN,
                    "value": value,
                    "source": source,
                    "attributes": result,
                }
        
        if "ip" in result:
            return {
                "type": AssetType.IP,
                "value": result["ip"],
                "source": source,
                "attributes": result,
            }
        
        if "port" in result:
            host = result.get("host", result.get("ip", ""))
            port = result["port"]
            return {
                "type": AssetType.PORT,
                "value": f"{host}:{port}",
                "source": source,
                "attributes": result,
            }
        
        if "url" in result or "endpoint" in result:
            return {
                "type": AssetType.ENDPOINT,
                "value": result.get("url") or result.get("endpoint"),
                "source": source,
                "attributes": result,
            }
        
        if "vulnerability" in result or "cve" in result:
            return {
                "type": AssetType.VULNERABILITY,
                "value": result.get("cve") or result.get("vulnerability", {}).get("id"),
                "source": source,
                "risk_level": self._detect_risk(result),
                "attributes": result,
            }
        
        return None
    
    def _detect_risk(self, result: Dict[str, Any]) -> RiskLevel:
        """اكتشاف مستوى الخطورة"""
        severity = result.get("severity", "").lower()
        
        if severity in ("critical", "crit"):
            return RiskLevel.CRITICAL
        elif severity in ("high", "hi"):
            return RiskLevel.HIGH
        elif severity in ("medium", "med"):
            return RiskLevel.MEDIUM
        elif severity in ("low", "lo"):
            return RiskLevel.LOW
        
        return RiskLevel.INFO
    
    # ─────────────────────────────────────────────────────────
    #                     Export/Import
    # ─────────────────────────────────────────────────────────
    
    def export(
        self,
        output_path: Union[str, Path],
        format: str = "json",
    ) -> int:
        """
        تصدير الأصول.
        
        Args:
            output_path: مسار الملف
            format: json, csv
        """
        assets = self.search(limit=100000)
        
        output_path = Path(output_path)
        
        if format == "json":
            data = {
                "exported_at": datetime.now().isoformat(),
                "count": len(assets),
                "assets": [a.to_dict() for a in assets],
            }
            
            with open(output_path, "w") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        
        elif format == "csv":
            import csv
            
            with open(output_path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "id", "type", "value", "status", "risk_level",
                    "source", "first_seen", "last_seen", "tags"
                ])
                
                for asset in assets:
                    writer.writerow([
                        asset.id, asset.type.value, asset.value,
                        asset.status.value, asset.risk_level.value,
                        asset.source, asset.first_seen.isoformat(),
                        asset.last_seen.isoformat(), ",".join(asset.tags)
                    ])
        
        logger.info("Exported %d assets to %s", len(assets), output_path)
        return len(assets)
    
    def import_file(
        self,
        input_path: Union[str, Path],
        format: str = "json",
    ) -> int:
        """
        استيراد الأصول.
        
        Args:
            input_path: مسار الملف
            format: json, csv
        """
        input_path = Path(input_path)
        imported = 0
        
        if format == "json":
            with open(input_path, "r") as f:
                data = json.load(f)
            
            assets = data.get("assets", [])
            for asset_data in assets:
                try:
                    self.add(
                        type=AssetType(asset_data["type"]),
                        value=asset_data["value"],
                        status=AssetStatus(asset_data.get("status", "unknown")),
                        risk_level=RiskLevel(asset_data.get("risk_level", "info")),
                        source=asset_data.get("source", "import"),
                        attributes=asset_data.get("attributes", {}),
                        tags=asset_data.get("tags", []),
                    )
                    imported += 1
                except Exception as e:
                    logger.warning("Failed to import asset: %s", e)
        
        elif format == "csv":
            import csv
            
            with open(input_path, "r") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    try:
                        self.add(
                            type=AssetType(row["type"]),
                            value=row["value"],
                            status=AssetStatus(row.get("status", "unknown")),
                            risk_level=RiskLevel(row.get("risk_level", "info")),
                            source=row.get("source", "import"),
                            tags=row.get("tags", "").split(","),
                        )
                        imported += 1
                    except Exception as e:
                        logger.warning("Failed to import row: %s", e)
        
        logger.info("Imported %d assets from %s", imported, input_path)
        return imported
    
    # ─────────────────────────────────────────────────────────
    #                     Statistics
    # ─────────────────────────────────────────────────────────
    
    def stats(self) -> Dict[str, Any]:
        """إحصائيات الجرد"""
        with self._get_conn() as conn:
            # Total count
            total = conn.execute(
                "SELECT COUNT(*) as cnt FROM assets"
            ).fetchone()["cnt"]
            
            # By type
            by_type = {}
            for row in conn.execute(
                "SELECT type, COUNT(*) as cnt FROM assets GROUP BY type"
            ):
                by_type[row["type"]] = row["cnt"]
            
            # By status
            by_status = {}
            for row in conn.execute(
                "SELECT status, COUNT(*) as cnt FROM assets GROUP BY status"
            ):
                by_status[row["status"]] = row["cnt"]
            
            # By risk
            by_risk = {}
            for row in conn.execute(
                "SELECT risk_level, COUNT(*) as cnt FROM assets GROUP BY risk_level"
            ):
                by_risk[row["risk_level"]] = row["cnt"]
            
            # Recent
            recent = conn.execute(
                """
                SELECT * FROM assets
                ORDER BY last_seen DESC
                LIMIT 5
                """
            ).fetchall()
            
            return {
                "total": total,
                "by_type": by_type,
                "by_status": by_status,
                "by_risk": by_risk,
                "recent": [self._row_to_asset(r).to_dict() for r in recent],
            }
    
    def _row_to_asset(self, row: sqlite3.Row) -> Asset:
        """تحويل صف إلى أصل"""
        return Asset(
            id=row["id"],
            type=AssetType(row["type"]),
            value=row["value"],
            status=AssetStatus(row["status"]),
            risk_level=RiskLevel(row["risk_level"]),
            confidence=row["confidence"],
            source=row["source"],
            first_seen=datetime.fromisoformat(row["first_seen"]),
            last_seen=datetime.fromisoformat(row["last_seen"]),
            parent_id=row["parent_id"],
            attributes=json.loads(row["attributes"]),
            tags=json.loads(row["tags"]),
            notes=row["notes"],
        )
