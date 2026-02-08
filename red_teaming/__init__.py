"""
AI Gateway Red Teaming Module
Automated adversarial testing for AI systems

Features:
- 50+ attack vectors across 8 categories
- Automated vulnerability scanning
- LLM-as-Judge evaluation
- Compliance mapping (OWASP Top 10 for LLMs, NIST AI RMF)
- Detailed security reports
"""

from .attacks import AttackLibrary, AttackCategory, AttackSeverity
from .scanner import RedTeamScanner, ScanConfig, ScanResult
from .evaluator import ResponseEvaluator, VulnerabilityRating
from .reports import ReportGenerator, SecurityReport
from .database import init_redteam_db, RedTeamDatabase

__all__ = [
    'AttackLibrary',
    'AttackCategory',
    'AttackSeverity',
    'RedTeamScanner',
    'ScanConfig',
    'ScanResult',
    'ResponseEvaluator',
    'VulnerabilityRating',
    'ReportGenerator',
    'SecurityReport',
    'init_redteam_db',
    'RedTeamDatabase'
]

__version__ = "1.0.0"
