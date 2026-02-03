from __future__ import annotations


FEATURE_KEYS = [
    "has_api",
    "has_login",
    "js_secrets_count",
    "url_count",
    "finding_count",
    "asn_score",
    "tag_entropy",
]

HIGH_RISK_ASNS = {
    "AS46606",
    "AS16276",
    "AS45102",
    "AS36351",
    "AS137409",
    "AS20473",
    "AS13414",
}


def compute_asn_score(asn: str | None) -> float:
    if not asn:
        return 0.0
    asn_upper = asn.upper()
    if asn_upper in HIGH_RISK_ASNS:
        return 0.9
    if asn_upper.startswith("AS1") or asn_upper.startswith("AS3"):
        return 0.6
    return 0.2
