"""
Search Engine for ReconnV2 Results.

Provides full-text search across:
- Findings
- Hosts
- Jobs
- Artifacts

Example:
    >>> from recon_cli.web.search import SearchEngine
    >>> engine = SearchEngine()
    >>> results = await engine.search("sql injection")
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from collections import defaultdict
import sqlite3

__all__ = [
    "SearchType",
    "SearchQuery",
    "SearchResult",
    "SearchHit",
    "SearchIndex",
    "SearchEngine",
    "SearchFilter",
    "SearchAggregation",
    "create_search_router",
]


class SearchType(Enum):
    """Types of searchable content."""
    
    FINDING = "finding"
    HOST = "host"
    JOB = "job"
    ARTIFACT = "artifact"
    LOG = "log"
    ALL = "all"


@dataclass
class SearchFilter:
    """Filter for search queries."""
    
    field: str
    operator: str  # eq, ne, gt, lt, gte, lte, in, contains
    value: Any
    
    def matches(self, doc: Dict[str, Any]) -> bool:
        """Check if document matches filter."""
        doc_value = doc.get(self.field)
        
        if doc_value is None:
            return False
        
        if self.operator == "eq":
            return doc_value == self.value
        elif self.operator == "ne":
            return doc_value != self.value
        elif self.operator == "gt":
            return doc_value > self.value
        elif self.operator == "lt":
            return doc_value < self.value
        elif self.operator == "gte":
            return doc_value >= self.value
        elif self.operator == "lte":
            return doc_value <= self.value
        elif self.operator == "in":
            return doc_value in self.value
        elif self.operator == "contains":
            return self.value.lower() in str(doc_value).lower()
        
        return False


@dataclass
class SearchQuery:
    """Search query specification."""
    
    query: str
    search_type: SearchType = SearchType.ALL
    filters: List[SearchFilter] = field(default_factory=list)
    limit: int = 100
    offset: int = 0
    sort_by: Optional[str] = None
    sort_order: str = "desc"  # asc or desc
    highlight: bool = True
    fields: Optional[List[str]] = None  # Specific fields to search
    
    @classmethod
    def parse(cls, query_string: str) -> "SearchQuery":
        """Parse a query string into a SearchQuery.
        
        Supports:
        - type:finding - filter by type
        - severity:high - filter by field
        - "exact phrase" - exact match
        - -exclude - exclude term
        """
        filters = []
        terms = []
        search_type = SearchType.ALL
        
        # Parse query parts
        parts = re.findall(r'(\w+):(\w+)|"([^"]+)"|(-?\w+)', query_string)
        
        for field, value, phrase, term in parts:
            if field and value:
                if field == "type":
                    try:
                        search_type = SearchType(value.lower())
                    except ValueError:
                        pass
                else:
                    filters.append(SearchFilter(
                        field=field,
                        operator="eq" if not value.startswith("*") else "contains",
                        value=value.strip("*"),
                    ))
            elif phrase:
                terms.append(f'"{phrase}"')
            elif term:
                terms.append(term)
        
        return cls(
            query=" ".join(terms),
            search_type=search_type,
            filters=filters,
        )
    
    def add_filter(
        self,
        field: str,
        value: Any,
        operator: str = "eq",
    ) -> "SearchQuery":
        """Add a filter to the query."""
        self.filters.append(SearchFilter(field=field, operator=operator, value=value))
        return self


@dataclass
class SearchHit:
    """Single search result hit."""
    
    doc_type: SearchType
    doc_id: str
    score: float
    document: Dict[str, Any]
    highlights: Dict[str, List[str]] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "type": self.doc_type.value,
            "id": self.doc_id,
            "score": self.score,
            "document": self.document,
            "highlights": self.highlights,
        }


@dataclass
class SearchAggregation:
    """Aggregation result."""
    
    field: str
    buckets: Dict[str, int] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "field": self.field,
            "buckets": [
                {"key": k, "count": v}
                for k, v in sorted(self.buckets.items(), key=lambda x: x[1], reverse=True)
            ],
        }


@dataclass
class SearchResult:
    """Search results container."""
    
    query: SearchQuery
    total: int
    hits: List[SearchHit] = field(default_factory=list)
    aggregations: Dict[str, SearchAggregation] = field(default_factory=dict)
    took_ms: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "query": self.query.query,
            "total": self.total,
            "hits": [h.to_dict() for h in self.hits],
            "aggregations": {k: v.to_dict() for k, v in self.aggregations.items()},
            "took_ms": self.took_ms,
        }
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


class SearchIndex:
    """In-memory search index with optional SQLite backing."""
    
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path
        self._documents: Dict[str, Dict[str, Any]] = {}
        self._inverted_index: Dict[str, Set[str]] = defaultdict(set)
        self._type_index: Dict[SearchType, Set[str]] = defaultdict(set)
        self._conn: Optional[sqlite3.Connection] = None
        
        if db_path:
            self._init_db()
    
    def _init_db(self) -> None:
        """Initialize SQLite database."""
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        self._conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts USING fts5(
                id, content, tokenize='porter'
            )
        """)
        self._conn.commit()
    
    def _tokenize(self, text: str) -> List[str]:
        """Tokenize text for indexing."""
        # Simple tokenization: lowercase, split on non-alphanumeric
        text = text.lower()
        tokens = re.findall(r'\w+', text)
        return tokens
    
    def _extract_text(self, doc: Dict[str, Any]) -> str:
        """Extract searchable text from document."""
        texts = []
        
        def extract(obj: Any, prefix: str = "") -> None:
            if isinstance(obj, str):
                texts.append(obj)
            elif isinstance(obj, dict):
                for k, v in obj.items():
                    extract(v, f"{prefix}.{k}" if prefix else k)
            elif isinstance(obj, list):
                for item in obj:
                    extract(item, prefix)
        
        extract(doc)
        return " ".join(texts)
    
    def index(
        self,
        doc_id: str,
        doc_type: SearchType,
        document: Dict[str, Any],
    ) -> None:
        """Index a document."""
        # Store document
        self._documents[doc_id] = {
            "type": doc_type,
            "document": document,
            "indexed_at": datetime.now(),
        }
        
        # Update type index
        self._type_index[doc_type].add(doc_id)
        
        # Update inverted index
        text = self._extract_text(document)
        tokens = self._tokenize(text)
        for token in tokens:
            self._inverted_index[token].add(doc_id)
        
        # SQLite FTS if enabled
        if self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO documents (id, type, content) VALUES (?, ?, ?)",
                (doc_id, doc_type.value, json.dumps(document)),
            )
            self._conn.execute(
                "INSERT OR REPLACE INTO documents_fts (id, content) VALUES (?, ?)",
                (doc_id, text),
            )
            self._conn.commit()
    
    def remove(self, doc_id: str) -> bool:
        """Remove a document from the index."""
        if doc_id not in self._documents:
            return False
        
        doc_data = self._documents.pop(doc_id)
        doc_type = doc_data["type"]
        
        # Update type index
        self._type_index[doc_type].discard(doc_id)
        
        # Update inverted index (expensive, but necessary)
        for token_docs in self._inverted_index.values():
            token_docs.discard(doc_id)
        
        # SQLite if enabled
        if self._conn:
            self._conn.execute("DELETE FROM documents WHERE id = ?", (doc_id,))
            self._conn.execute("DELETE FROM documents_fts WHERE id = ?", (doc_id,))
            self._conn.commit()
        
        return True
    
    def search(self, query: SearchQuery) -> SearchResult:
        """Search the index."""
        start_time = datetime.now()
        
        # Get candidate documents
        if query.search_type == SearchType.ALL:
            candidates = set(self._documents.keys())
        else:
            candidates = self._type_index.get(query.search_type, set()).copy()
        
        # Apply text search
        if query.query.strip():
            query_tokens = self._tokenize(query.query)
            if query_tokens:
                matching_docs: Set[str] = set()
                for token in query_tokens:
                    if token.startswith("-"):
                        # Exclude term
                        exclude_token = token[1:]
                        candidates -= self._inverted_index.get(exclude_token, set())
                    else:
                        # Include term
                        token_matches = self._inverted_index.get(token, set())
                        if not matching_docs:
                            matching_docs = token_matches.copy()
                        else:
                            # Require all terms (AND)
                            matching_docs &= token_matches
                
                candidates &= matching_docs
        
        # Apply filters
        filtered_docs = []
        for doc_id in candidates:
            doc_data = self._documents.get(doc_id)
            if not doc_data:
                continue
            
            document = doc_data["document"]
            
            # Check all filters
            if all(f.matches(document) for f in query.filters):
                filtered_docs.append((doc_id, doc_data))
        
        # Calculate scores
        scored_docs = []
        for doc_id, doc_data in filtered_docs:
            score = self._calculate_score(query, doc_data["document"])
            scored_docs.append((doc_id, doc_data, score))
        
        # Sort
        if query.sort_by:
            scored_docs.sort(
                key=lambda x: x[1]["document"].get(query.sort_by, ""),
                reverse=(query.sort_order == "desc"),
            )
        else:
            scored_docs.sort(key=lambda x: x[2], reverse=True)
        
        # Apply pagination
        total = len(scored_docs)
        paginated = scored_docs[query.offset:query.offset + query.limit]
        
        # Build hits
        hits = []
        for doc_id, doc_data, score in paginated:
            highlights = {}
            if query.highlight:
                highlights = self._generate_highlights(query, doc_data["document"])
            
            hits.append(SearchHit(
                doc_type=doc_data["type"],
                doc_id=doc_id,
                score=score,
                document=doc_data["document"],
                highlights=highlights,
            ))
        
        # Calculate aggregations
        aggregations = self._calculate_aggregations(filtered_docs)
        
        took_ms = (datetime.now() - start_time).total_seconds() * 1000
        
        return SearchResult(
            query=query,
            total=total,
            hits=hits,
            aggregations=aggregations,
            took_ms=took_ms,
        )
    
    def _calculate_score(self, query: SearchQuery, document: Dict[str, Any]) -> float:
        """Calculate relevance score for a document."""
        if not query.query.strip():
            return 1.0
        
        text = self._extract_text(document).lower()
        query_lower = query.query.lower()
        
        # Simple TF-IDF-like scoring
        score = 0.0
        tokens = self._tokenize(query.query)
        
        for token in tokens:
            if token.startswith("-"):
                continue
            
            # Term frequency
            tf = text.count(token)
            
            # Inverse document frequency
            doc_count = len(self._inverted_index.get(token, set()))
            total_docs = len(self._documents) or 1
            idf = 1 + (total_docs / (doc_count + 1))
            
            score += tf * idf
        
        # Boost for exact phrase match
        if query_lower in text:
            score *= 2
        
        return score
    
    def _generate_highlights(
        self,
        query: SearchQuery,
        document: Dict[str, Any],
    ) -> Dict[str, List[str]]:
        """Generate highlighted snippets."""
        highlights: Dict[str, List[str]] = {}
        tokens = [t for t in self._tokenize(query.query) if not t.startswith("-")]
        
        if not tokens:
            return highlights
        
        def find_highlights(obj: Any, path: str = "") -> None:
            if isinstance(obj, str):
                snippets = []
                text_lower = obj.lower()
                for token in tokens:
                    if token in text_lower:
                        # Find context around match
                        idx = text_lower.find(token)
                        start = max(0, idx - 30)
                        end = min(len(obj), idx + len(token) + 30)
                        snippet = obj[start:end]
                        
                        # Highlight the match
                        pattern = re.compile(re.escape(token), re.IGNORECASE)
                        highlighted = pattern.sub(f"<mark>{token}</mark>", snippet)
                        
                        if snippet != obj:
                            highlighted = f"...{highlighted}..."
                        
                        snippets.append(highlighted)
                
                if snippets:
                    highlights[path] = snippets
            
            elif isinstance(obj, dict):
                for k, v in obj.items():
                    new_path = f"{path}.{k}" if path else k
                    find_highlights(v, new_path)
            
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    find_highlights(item, f"{path}[{i}]")
        
        find_highlights(document)
        return highlights
    
    def _calculate_aggregations(
        self,
        docs: List[Tuple[str, Dict[str, Any]]],
    ) -> Dict[str, SearchAggregation]:
        """Calculate aggregations for search results."""
        aggregations = {}
        
        # Aggregate by type
        type_agg = SearchAggregation(field="type")
        for _, doc_data in docs:
            doc_type = doc_data["type"].value
            type_agg.buckets[doc_type] = type_agg.buckets.get(doc_type, 0) + 1
        aggregations["type"] = type_agg
        
        # Aggregate by severity (if present)
        severity_agg = SearchAggregation(field="severity")
        for _, doc_data in docs:
            severity = doc_data["document"].get("severity")
            if severity:
                severity_agg.buckets[severity] = severity_agg.buckets.get(severity, 0) + 1
        if severity_agg.buckets:
            aggregations["severity"] = severity_agg
        
        return aggregations
    
    def clear(self) -> None:
        """Clear all indexed documents."""
        self._documents.clear()
        self._inverted_index.clear()
        self._type_index.clear()
        
        if self._conn:
            self._conn.execute("DELETE FROM documents")
            self._conn.execute("DELETE FROM documents_fts")
            self._conn.commit()
    
    @property
    def document_count(self) -> int:
        """Get total document count."""
        return len(self._documents)


class SearchEngine:
    """High-level search engine with async support."""
    
    def __init__(
        self,
        db_path: Optional[Path] = None,
        jobs_dir: Optional[Path] = None,
    ):
        self.index = SearchIndex(db_path)
        self.jobs_dir = jobs_dir
        self._indexed_jobs: Set[str] = set()
    
    async def search(
        self,
        query: Union[str, SearchQuery],
        limit: int = 100,
        offset: int = 0,
    ) -> SearchResult:
        """Perform async search."""
        if isinstance(query, str):
            query = SearchQuery.parse(query)
        
        query.limit = limit
        query.offset = offset
        
        # Run search in thread pool for SQLite
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, self.index.search, query)
        return result
    
    async def index_job(self, job_id: str, job_data: Dict[str, Any]) -> int:
        """Index a job and its findings."""
        indexed_count = 0
        
        # Index job metadata
        self.index.index(
            doc_id=f"job:{job_id}",
            doc_type=SearchType.JOB,
            document={
                "id": job_id,
                "name": job_data.get("name", ""),
                "status": job_data.get("status", ""),
                "targets": job_data.get("targets", []),
                "created_at": job_data.get("created_at", ""),
            },
        )
        indexed_count += 1
        
        # Index findings
        findings = job_data.get("findings", [])
        for i, finding in enumerate(findings):
            self.index.index(
                doc_id=f"finding:{job_id}:{i}",
                doc_type=SearchType.FINDING,
                document={
                    "job_id": job_id,
                    **finding,
                },
            )
            indexed_count += 1
        
        # Index hosts
        hosts = job_data.get("hosts", [])
        for host in hosts:
            host_id = host.get("ip") or host.get("hostname", "")
            self.index.index(
                doc_id=f"host:{job_id}:{host_id}",
                doc_type=SearchType.HOST,
                document={
                    "job_id": job_id,
                    **host,
                },
            )
            indexed_count += 1
        
        self._indexed_jobs.add(job_id)
        return indexed_count
    
    async def index_from_directory(self, jobs_dir: Optional[Path] = None) -> int:
        """Index all jobs from directory."""
        jobs_dir = jobs_dir or self.jobs_dir
        if not jobs_dir or not jobs_dir.exists():
            return 0
        
        indexed_count = 0
        finished_dir = jobs_dir / "finished"
        
        if finished_dir.exists():
            for job_dir in finished_dir.iterdir():
                if not job_dir.is_dir():
                    continue
                
                job_id = job_dir.name
                if job_id in self._indexed_jobs:
                    continue
                
                # Load job data
                metadata_file = job_dir / "metadata.json"
                results_file = job_dir / "results.jsonl"
                
                job_data = {}
                
                if metadata_file.exists():
                    with open(metadata_file) as f:
                        job_data.update(json.load(f))
                
                if results_file.exists():
                    findings = []
                    with open(results_file) as f:
                        for line in f:
                            if line.strip():
                                findings.append(json.loads(line))
                    job_data["findings"] = findings
                
                if job_data:
                    count = await self.index_job(job_id, job_data)
                    indexed_count += count
        
        return indexed_count
    
    async def reindex_all(self) -> int:
        """Reindex all documents."""
        self.index.clear()
        self._indexed_jobs.clear()
        return await self.index_from_directory()
    
    def suggest(self, prefix: str, limit: int = 10) -> List[str]:
        """Get search suggestions based on prefix."""
        prefix_lower = prefix.lower()
        suggestions = []
        
        for token in self.index._inverted_index.keys():
            if token.startswith(prefix_lower):
                suggestions.append(token)
                if len(suggestions) >= limit:
                    break
        
        return suggestions


def create_search_router():
    """Create FastAPI router for search endpoints."""
    try:
        from fastapi import APIRouter, Query, HTTPException
    except ImportError:
        raise ImportError("FastAPI is required for search router")
    
    router = APIRouter(prefix="/search", tags=["search"])
    engine = SearchEngine()
    
    @router.get("/")
    async def search(
        q: str = Query("", description="Search query"),
        type: Optional[str] = Query(None, description="Filter by type"),
        limit: int = Query(100, le=1000),
        offset: int = Query(0, ge=0),
    ):
        """Search across all indexed content."""
        if not q:
            raise HTTPException(400, "Query parameter 'q' is required")
        query = SearchQuery.parse(q)
        
        if type:
            try:
                query.search_type = SearchType(type)
            except ValueError:
                raise HTTPException(400, f"Invalid type: {type}")
        
        query.limit = limit
        query.offset = offset
        
        result = await engine.search(query)
        return result.to_dict()
    
    @router.get("/suggest")
    async def suggest(
        q: str = Query("", description="Search prefix"),
        limit: int = Query(10, le=50),
    ):
        """Get search suggestions."""
        if not q:
            raise HTTPException(400, "Query parameter 'q' is required")
        suggestions = engine.suggest(q, limit)
        return {"suggestions": suggestions}
    
    @router.post("/reindex")
    async def reindex():
        """Reindex all documents."""
        count = await engine.reindex_all()
        return {"indexed": count}
    
    return router
