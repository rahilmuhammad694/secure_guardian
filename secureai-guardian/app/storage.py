"""
SecureAI Guardian - In-Memory Storage (MongoDB fallback)
"""

from typing import Dict, List, Optional, Any
from datetime import datetime
import uuid
from collections import defaultdict


class InMemoryStore:
    """Thread-safe in-memory data store for demo/testing."""

    def __init__(self):
        self.collections: Dict[str, Dict[str, Any]] = defaultdict(dict)
        self.data = {}
    def seed(self):
        self._seed_demo_data()

    def _seed_demo_data(self):
        """Seed with realistic demo data."""
        from app.security import get_password_hash
        
        # Default admin user
        admin_id = str(uuid.uuid4())
        self.collections["users"][admin_id] = {
            "_id": admin_id,
            "username": "admin",
            "email": "admin@secureai.io",
            "hashed_password": get_password_hash("admin123"),
            "role": "admin",
            "created_at": datetime.utcnow().isoformat(),
        }

        analyst_id = str(uuid.uuid4())
        self.collections["users"][analyst_id] = {
            "_id": analyst_id,
            "username": "analyst",
            "email": "analyst@secureai.io",
            "hashed_password":  get_password_hash("analyst123"),
            "role": "analyst",
            "created_at": datetime.utcnow().isoformat(),
        }

        # Seed demo logs
        demo_logs = [
            {
                "source_ip": "192.168.1.105",
                "event_type": "failed_login",
                "message": "Multiple failed SSH login attempts from 192.168.1.105",
                "severity": "high",
                "status_code": 401,
            },
            {
                "source_ip": "10.0.0.52",
                "event_type": "sql_query",
                "message": "Suspicious SQL query detected: SELECT * FROM users WHERE id=1 OR 1=1",
                "severity": "critical",
                "status_code": 200,
            },
            {
                "source_ip": "172.16.0.200",
                "event_type": "port_scan",
                "message": "Port scanning detected from external IP 172.16.0.200",
                "severity": "medium",
                "status_code": None,
            },
            {
                "source_ip": "192.168.1.30",
                "event_type": "data_transfer",
                "message": "Unusual large data transfer: 2.4GB sent to external IP",
                "severity": "critical",
                "bytes_transferred": 2400000000,
            },
            {
                "source_ip": "10.10.0.88",
                "event_type": "privilege_escalation",
                "message": "User attempted to access /etc/shadow without permissions",
                "severity": "high",
                "status_code": 403,
            },
            {
                "source_ip": "203.0.113.45",
                "event_type": "ddos",
                "message": "DDoS attack pattern detected: 50,000 requests/min from botnet",
                "severity": "critical",
                "status_code": None,
            },
            {
                "source_ip": "192.168.2.15",
                "event_type": "malware",
                "message": "Malware signature detected in uploaded file: Trojan.GenericKD",
                "severity": "critical",
                "status_code": 200,
            },
            {
                "source_ip": "10.0.1.75",
                "event_type": "xss_attempt",
                "message": "XSS attempt: <script>document.cookie</script> in user input",
                "severity": "high",
                "status_code": 400,
            },
        ]

        log_ids = []
        for i, log_data in enumerate(demo_logs):
            log_id = str(uuid.uuid4())
            from datetime import timedelta
            ts = datetime.utcnow() - timedelta(hours=i * 2, minutes=i * 15)
            self.collections["logs"][log_id] = {
                "_id": log_id,
                "timestamp": ts.isoformat(),
                "destination_ip": "10.0.0.1",
                "user_agent": "Mozilla/5.0",
                **log_data,
            }
            log_ids.append(log_id)

        # Seed demo threats
        demo_threats = [
            {
                "threat_category": "brute_force",
                "severity": "high",
                "risk_score": 78.5,
                "confidence": 0.92,
                "source_ips": ["192.168.1.105"],
                "description": "Brute force SSH attack detected with 847 failed attempts in 10 minutes",
                "status": "open",
            },
            {
                "threat_category": "sql_injection",
                "severity": "critical",
                "risk_score": 95.2,
                "confidence": 0.98,
                "source_ips": ["10.0.0.52"],
                "description": "SQL injection attack targeting user authentication endpoint",
                "status": "investigating",
            },
            {
                "threat_category": "ddos",
                "severity": "critical",
                "risk_score": 91.0,
                "confidence": 0.95,
                "source_ips": ["203.0.113.45"],
                "description": "Distributed denial-of-service attack from botnet infrastructure",
                "status": "mitigated",
            },
            {
                "threat_category": "data_exfiltration",
                "severity": "critical",
                "risk_score": 88.7,
                "confidence": 0.87,
                "source_ips": ["192.168.1.30"],
                "description": "Suspected data exfiltration: 2.4GB transferred to unknown external endpoint",
                "status": "open",
            },
            {
                "threat_category": "malware",
                "severity": "critical",
                "risk_score": 96.1,
                "confidence": 0.99,
                "source_ips": ["192.168.2.15"],
                "description": "Trojan malware detected and quarantined on endpoint",
                "status": "resolved",
            },
        ]

        for i, threat_data in enumerate(demo_threats):
            threat_id = str(uuid.uuid4())
            from datetime import timedelta
            ts = datetime.utcnow() - timedelta(hours=i * 3)
            self.collections["threats"][threat_id] = {
                "_id": threat_id,
                "detected_at": ts.isoformat(),
                "log_ids": log_ids[:2],
                "indicators": [],
                "assigned_to": "admin",
                **threat_data,
            }

    # ── CRUD helpers ──────────────────────────────────────────────────────────

    def insert_one(self, collection: str, document: dict) -> str:
        doc_id = document.get("_id") or str(uuid.uuid4())
        document["_id"] = doc_id
        self.collections[collection][doc_id] = document
        return doc_id

    def find_one(self, collection: str, query: dict) -> Optional[dict]:
        for doc in self.collections[collection].values():
            if all(doc.get(k) == v for k, v in query.items()):
                return doc
        return None

    def find(self, collection: str, query: dict = None, limit: int = 1000, skip: int = 0) -> List[dict]:
        docs = list(self.collections[collection].values())
        if query:
            docs = [d for d in docs if all(d.get(k) == v for k, v in query.items())]
        return docs[skip: skip + limit]

    def update_one(self, collection: str, query: dict, update: dict) -> bool:
        doc = self.find_one(collection, query)
        if doc:
            doc_id = doc["_id"]
            self.collections[collection][doc_id].update(update.get("$set", {}))
            return True
        return False

    def count(self, collection: str, query: dict = None) -> int:
        return len(self.find(collection, query, limit=100000))

    def delete_one(self, collection: str, query: dict) -> bool:
        doc = self.find_one(collection, query)
        if doc:
            del self.collections[collection][doc["_id"]]
            return True
        return False


# Global in-memory store instance
memory_store = InMemoryStore()
memory_store.seed()