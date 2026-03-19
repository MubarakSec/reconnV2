from __future__ import annotations


"""
Secrets Detector Module - كشف الأسرار والبيانات الحساسة

يكتشف الأسرار المخزنة بشكل خاطئ في الكود مثل:
- AWS Access Keys و Secret Keys
- Slack Tokens
- Google API Keys
- JWT Tokens
- RSA Private Keys
- أي secret/token/api_key عام

يستخدم:
1. Pattern Matching (Regex) للأنماط المعروفة
2. Shannon Entropy لاكتشاف السلاسل العشوائية

Example:
    >>> detector = SecretsDetector()
    >>> matches = detector.scan_text("const API_KEY = 'AKIAIOSFODNN7EXAMPLE'")
    >>> for m in matches:
    ...     print(f"{m.pattern}: confidence={m.confidence}")
"""
