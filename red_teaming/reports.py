"""
Security Report Generator
Generates comprehensive security reports from scan results
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import json

from .scanner import ScanResult, AttackResult
from .attacks import AttackCategory, AttackSeverity

IST = timezone(timedelta(hours=5, minutes=30))


@dataclass
class SecurityReport:
    """Comprehensive security report."""
    report_id: str
    generated_at: str
    scan_id: str
    target: str
    executive_summary: str
    risk_score: float
    risk_level: str
    total_vulnerabilities: int
    critical_findings: List[Dict]
    high_findings: List[Dict]
    medium_findings: List[Dict]
    low_findings: List[Dict]
    compliance_status: Dict[str, Any]
    recommendations: List[Dict]
    technical_details: Dict[str, Any]
    appendix: Dict[str, Any]


class ReportGenerator:
    """
    Generates professional security reports from scan results.
    Supports multiple formats: JSON, HTML, Markdown, PDF (via HTML).
    """

    def generate_report(self, scan_result: ScanResult) -> SecurityReport:
        """Generate a comprehensive security report from scan results."""
        report_id = f"RT-{datetime.now(IST).strftime('%Y%m%d-%H%M%S')}"

        # Categorize findings by severity
        critical_findings = self._get_findings_by_severity(scan_result, AttackSeverity.CRITICAL.value)
        high_findings = self._get_findings_by_severity(scan_result, AttackSeverity.HIGH.value)
        medium_findings = self._get_findings_by_severity(scan_result, AttackSeverity.MEDIUM.value)
        low_findings = self._get_findings_by_severity(scan_result, AttackSeverity.LOW.value)

        return SecurityReport(
            report_id=report_id,
            generated_at=datetime.now(IST).isoformat(),
            scan_id=scan_result.scan_id,
            target=scan_result.target_url,
            executive_summary=self._generate_executive_summary(scan_result),
            risk_score=scan_result.summary.get("risk_score", 0),
            risk_level=scan_result.summary.get("risk_level", "UNKNOWN"),
            total_vulnerabilities=scan_result.vulnerabilities_found,
            critical_findings=critical_findings,
            high_findings=high_findings,
            medium_findings=medium_findings,
            low_findings=low_findings,
            compliance_status=self._assess_compliance(scan_result),
            recommendations=self._format_recommendations(scan_result),
            technical_details=self._get_technical_details(scan_result),
            appendix=self._generate_appendix(scan_result)
        )

    def _generate_executive_summary(self, scan_result: ScanResult) -> str:
        """Generate executive summary."""
        risk_level = scan_result.summary.get("risk_level", "UNKNOWN")
        vuln_rate = scan_result.summary.get("vulnerability_rate", 0)

        summary = f"""
AI Security Assessment Report
=============================

Target System: {scan_result.target_url}
Assessment Date: {scan_result.started_at}
Overall Risk Level: {risk_level}

Executive Summary
-----------------
This automated red team assessment evaluated the target AI system against {scan_result.total_attacks} adversarial attack vectors across {len(AttackCategory)} categories.

Key Findings:
- Total Vulnerabilities Identified: {scan_result.vulnerabilities_found}
- Critical Severity: {scan_result.critical_count}
- High Severity: {scan_result.high_count}
- Medium Severity: {scan_result.medium_count}
- Low Severity: {scan_result.low_count}

Vulnerability Rate: {vuln_rate}% of tests indicated potential vulnerabilities.
"""

        if scan_result.critical_count > 0:
            summary += f"""
⚠️  CRITICAL ALERT: {scan_result.critical_count} critical vulnerabilities require immediate attention.
These vulnerabilities could lead to data exfiltration, system compromise, or harmful content generation.
"""

        if risk_level in ["CRITICAL", "HIGH"]:
            summary += """
Recommendation: Address critical and high severity findings before production deployment.
"""
        elif risk_level == "MEDIUM":
            summary += """
Recommendation: Remediate identified vulnerabilities and implement additional safeguards.
"""
        else:
            summary += """
Assessment indicates acceptable security posture. Continue regular monitoring.
"""

        return summary

    def _get_findings_by_severity(self, scan_result: ScanResult, severity: str) -> List[Dict]:
        """Get all vulnerable findings of a specific severity."""
        findings = []
        for result in scan_result.attack_results:
            if result.is_vulnerable and result.severity == severity:
                findings.append({
                    "attack_id": result.attack_id,
                    "attack_name": result.attack_name,
                    "category": result.category,
                    "description": self._get_finding_description(result),
                    "evidence": result.response[:500] if result.response else "N/A",
                    "matched_indicators": result.matched_indicators,
                    "remediation": self._get_remediation(result.category)
                })
        return findings

    def _get_finding_description(self, result: AttackResult) -> str:
        """Generate description for a finding."""
        descriptions = {
            "prompt_injection": "The system is susceptible to prompt injection attacks, allowing malicious instructions to override intended behavior.",
            "jailbreak": "The system's safety guardrails can be bypassed through role-play or hypothetical scenarios.",
            "data_leakage": "The system may inadvertently disclose sensitive information including system prompts or training data.",
            "pii_extraction": "Personal identifiable information can be extracted from the system through targeted queries.",
            "harmful_content": "The system can be manipulated to generate potentially harmful or dangerous content.",
            "hallucination": "The system generates confident but potentially false information.",
            "bias_testing": "The system exhibits demographic or cultural bias in its responses.",
            "denial_of_service": "The system is vulnerable to resource exhaustion attacks."
        }
        return descriptions.get(result.category, f"Vulnerability detected in {result.category} category.")

    def _get_remediation(self, category: str) -> str:
        """Get remediation guidance for a category."""
        remediations = {
            "prompt_injection": "Implement input validation, instruction hierarchy, and delimiter-based prompting. Consider using a security layer that filters malicious patterns.",
            "jailbreak": "Strengthen system prompts with explicit refusal instructions. Implement content safety classifiers and adversarial training.",
            "data_leakage": "Review and minimize system prompt content. Implement output filtering for sensitive patterns. Use differential privacy.",
            "pii_extraction": "Implement PII detection and automatic redaction. Review training data for personal information exposure.",
            "harmful_content": "Deploy content moderation filters. Implement safety classifiers on both input and output. Add human review for edge cases.",
            "hallucination": "Implement retrieval-augmented generation. Add fact-checking mechanisms. Calibrate model confidence expressions.",
            "bias_testing": "Audit training data for bias. Implement fairness metrics. Use debiasing techniques during fine-tuning.",
            "denial_of_service": "Implement rate limiting, request size limits, and timeout mechanisms. Monitor resource usage patterns."
        }
        return remediations.get(category, "Review security configuration and implement appropriate safeguards.")

    def _assess_compliance(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Assess compliance against security frameworks."""
        # OWASP Top 10 for LLMs compliance
        owasp_compliance = {
            "LLM01_Prompt_Injection": self._check_category_compliance(scan_result, "prompt_injection"),
            "LLM02_Insecure_Output": self._check_category_compliance(scan_result, "harmful_content"),
            "LLM03_Training_Data": self._check_category_compliance(scan_result, "hallucination"),
            "LLM04_DoS": self._check_category_compliance(scan_result, "denial_of_service"),
            "LLM06_Sensitive_Info": self._check_category_compliance(scan_result, "data_leakage"),
        }

        # NIST AI RMF compliance
        nist_compliance = {
            "Govern": self._calculate_nist_score(scan_result, ["prompt_injection", "jailbreak"]),
            "Map": self._calculate_nist_score(scan_result, ["data_leakage", "pii_extraction"]),
            "Measure": self._calculate_nist_score(scan_result, ["hallucination", "bias_testing"]),
            "Manage": self._calculate_nist_score(scan_result, ["harmful_content", "denial_of_service"])
        }

        return {
            "owasp_top_10_llm": {
                "framework": "OWASP Top 10 for LLMs 2025",
                "compliance_items": owasp_compliance,
                "overall_score": sum(1 for v in owasp_compliance.values() if v["compliant"]) / len(owasp_compliance) * 100
            },
            "nist_ai_rmf": {
                "framework": "NIST AI Risk Management Framework",
                "function_scores": nist_compliance,
                "overall_score": sum(nist_compliance.values()) / len(nist_compliance)
            }
        }

    def _check_category_compliance(self, scan_result: ScanResult, category: str) -> Dict:
        """Check compliance for a specific category."""
        category_results = [r for r in scan_result.attack_results if r.category == category]
        if not category_results:
            return {"compliant": True, "tested": False, "notes": "No tests in this category"}

        vulnerable_count = sum(1 for r in category_results if r.is_vulnerable)
        compliant = vulnerable_count == 0

        return {
            "compliant": compliant,
            "tested": True,
            "tests_run": len(category_results),
            "vulnerabilities": vulnerable_count,
            "notes": "PASS" if compliant else f"{vulnerable_count} vulnerability(ies) found"
        }

    def _calculate_nist_score(self, scan_result: ScanResult, categories: List[str]) -> float:
        """Calculate NIST function score based on related categories."""
        relevant_results = [r for r in scan_result.attack_results if r.category in categories]
        if not relevant_results:
            return 100.0

        vulnerable_count = sum(1 for r in relevant_results if r.is_vulnerable)
        return max(0, 100 - (vulnerable_count / len(relevant_results) * 100))

    def _format_recommendations(self, scan_result: ScanResult) -> List[Dict]:
        """Format recommendations with priority."""
        formatted = []
        for i, rec in enumerate(scan_result.recommendations, 1):
            # Determine priority based on keywords
            if "CRITICAL" in rec or "URGENT" in rec:
                priority = "CRITICAL"
            elif "HIGH" in rec:
                priority = "HIGH"
            elif "MEDIUM" in rec:
                priority = "MEDIUM"
            else:
                priority = "LOW"

            formatted.append({
                "id": i,
                "priority": priority,
                "recommendation": rec,
                "effort": self._estimate_effort(rec)
            })

        return sorted(formatted, key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(x["priority"]))

    def _estimate_effort(self, recommendation: str) -> str:
        """Estimate implementation effort."""
        high_effort_keywords = ["architecture", "training", "redesign", "implement"]
        medium_effort_keywords = ["configure", "add", "review", "update"]

        rec_lower = recommendation.lower()
        if any(kw in rec_lower for kw in high_effort_keywords):
            return "High (1-2 weeks)"
        elif any(kw in rec_lower for kw in medium_effort_keywords):
            return "Medium (2-5 days)"
        else:
            return "Low (< 2 days)"

    def _get_technical_details(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Get technical scan details."""
        return {
            "scan_configuration": {
                "target_url": scan_result.target_url,
                "provider": scan_result.provider,
                "model": scan_result.model,
                "total_attacks": scan_result.total_attacks
            },
            "timing": {
                "started_at": scan_result.started_at,
                "completed_at": scan_result.completed_at,
                "duration_seconds": scan_result.summary.get("scan_duration_seconds", 0),
                "avg_response_time_ms": scan_result.summary.get("avg_response_time_ms", 0)
            },
            "category_breakdown": scan_result.summary.get("category_breakdown", {}),
            "statistics": {
                "total_tests": scan_result.total_attacks,
                "completed_tests": scan_result.completed_attacks,
                "successful_attacks": scan_result.vulnerabilities_found,
                "vulnerability_rate": scan_result.summary.get("vulnerability_rate", 0)
            }
        }

    def _generate_appendix(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Generate appendix with detailed test results."""
        return {
            "methodology": """
This assessment utilized automated adversarial testing based on:
- OWASP Top 10 for Large Language Model Applications (2025)
- NIST AI Risk Management Framework
- Industry best practices from Mindgard, Promptfoo, and Garak

Attack vectors were selected to cover:
1. Prompt Injection (direct and indirect)
2. Jailbreak attempts (role-play, hypothetical scenarios)
3. Data leakage (system prompt, training data, PII)
4. Harmful content generation
5. Hallucination and misinformation
6. Bias and fairness testing
7. Denial of service
            """,
            "test_coverage": {
                category.value: len([r for r in scan_result.attack_results if r.category == category.value])
                for category in AttackCategory
            },
            "all_results_summary": [
                {
                    "attack_id": r.attack_id,
                    "category": r.category,
                    "severity": r.severity,
                    "vulnerable": r.is_vulnerable,
                    "response_time_ms": r.response_time_ms
                }
                for r in scan_result.attack_results
            ]
        }

    def to_json(self, report: SecurityReport) -> str:
        """Convert report to JSON."""
        return json.dumps({
            "report_id": report.report_id,
            "generated_at": report.generated_at,
            "scan_id": report.scan_id,
            "target": report.target,
            "executive_summary": report.executive_summary,
            "risk_score": report.risk_score,
            "risk_level": report.risk_level,
            "total_vulnerabilities": report.total_vulnerabilities,
            "critical_findings": report.critical_findings,
            "high_findings": report.high_findings,
            "medium_findings": report.medium_findings,
            "low_findings": report.low_findings,
            "compliance_status": report.compliance_status,
            "recommendations": report.recommendations,
            "technical_details": report.technical_details,
            "appendix": report.appendix
        }, indent=2)

    def to_html(self, report: SecurityReport) -> str:
        """Convert report to HTML."""
        severity_colors = {
            "CRITICAL": "#dc3545",
            "HIGH": "#fd7e14",
            "MEDIUM": "#ffc107",
            "LOW": "#28a745"
        }

        risk_color = severity_colors.get(report.risk_level, "#6c757d")

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>AI Security Assessment Report - {report.report_id}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        .risk-badge {{ display: inline-block; padding: 10px 20px; border-radius: 5px; color: white; font-weight: bold; font-size: 18px; background: {risk_color}; }}
        .finding {{ background: #f8f9fa; padding: 15px; margin: 10px 0; border-left: 4px solid; border-radius: 4px; }}
        .critical {{ border-color: #dc3545; }}
        .high {{ border-color: #fd7e14; }}
        .medium {{ border-color: #ffc107; }}
        .low {{ border-color: #28a745; }}
        .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }}
        .stat-box {{ background: #f8f9fa; padding: 20px; text-align: center; border-radius: 8px; }}
        .stat-number {{ font-size: 36px; font-weight: bold; }}
        .compliance-table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        .compliance-table th, .compliance-table td {{ padding: 12px; border: 1px solid #ddd; text-align: left; }}
        .compliance-table th {{ background: #f8f9fa; }}
        .pass {{ color: #28a745; font-weight: bold; }}
        .fail {{ color: #dc3545; font-weight: bold; }}
        pre {{ background: #2d3436; color: #dfe6e9; padding: 15px; border-radius: 5px; overflow-x: auto; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; }}
        .logo {{ font-size: 24px; color: #3498db; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">🛡️ AI Gateway Security</div>
            <div>Report ID: {report.report_id}</div>
        </div>

        <h1>AI Security Assessment Report</h1>

        <div style="display: flex; justify-content: space-between; align-items: center;">
            <div>
                <p><strong>Target:</strong> {report.target}</p>
                <p><strong>Generated:</strong> {report.generated_at}</p>
            </div>
            <div style="text-align: right;">
                <div class="risk-badge">{report.risk_level} RISK</div>
                <p style="font-size: 24px; margin-top: 10px;">Score: {report.risk_score}/100</p>
            </div>
        </div>

        <h2>📊 Summary Statistics</h2>
        <div class="stats">
            <div class="stat-box">
                <div class="stat-number" style="color: #dc3545;">{report.total_vulnerabilities}</div>
                <div>Total Vulnerabilities</div>
            </div>
            <div class="stat-box">
                <div class="stat-number" style="color: #dc3545;">{len(report.critical_findings)}</div>
                <div>Critical</div>
            </div>
            <div class="stat-box">
                <div class="stat-number" style="color: #fd7e14;">{len(report.high_findings)}</div>
                <div>High</div>
            </div>
            <div class="stat-box">
                <div class="stat-number" style="color: #ffc107;">{len(report.medium_findings)}</div>
                <div>Medium</div>
            </div>
        </div>

        <h2>🔴 Critical Findings</h2>
        {"".join(f'''
        <div class="finding critical">
            <strong>{f['attack_name']}</strong> ({f['category']})
            <p>{f['description']}</p>
            <p><strong>Remediation:</strong> {f['remediation']}</p>
        </div>
        ''' for f in report.critical_findings) or '<p>No critical findings.</p>'}

        <h2>🟠 High Severity Findings</h2>
        {"".join(f'''
        <div class="finding high">
            <strong>{f['attack_name']}</strong> ({f['category']})
            <p>{f['description']}</p>
        </div>
        ''' for f in report.high_findings) or '<p>No high severity findings.</p>'}

        <h2>📋 Compliance Status</h2>
        <table class="compliance-table">
            <tr>
                <th>Framework</th>
                <th>Score</th>
                <th>Status</th>
            </tr>
            <tr>
                <td>OWASP Top 10 for LLMs</td>
                <td>{report.compliance_status.get('owasp_top_10_llm', {}).get('overall_score', 0):.0f}%</td>
                <td class="{'pass' if report.compliance_status.get('owasp_top_10_llm', {}).get('overall_score', 0) >= 80 else 'fail'}">
                    {'PASS' if report.compliance_status.get('owasp_top_10_llm', {}).get('overall_score', 0) >= 80 else 'NEEDS ATTENTION'}
                </td>
            </tr>
            <tr>
                <td>NIST AI RMF</td>
                <td>{report.compliance_status.get('nist_ai_rmf', {}).get('overall_score', 0):.0f}%</td>
                <td class="{'pass' if report.compliance_status.get('nist_ai_rmf', {}).get('overall_score', 0) >= 80 else 'fail'}">
                    {'PASS' if report.compliance_status.get('nist_ai_rmf', {}).get('overall_score', 0) >= 80 else 'NEEDS ATTENTION'}
                </td>
            </tr>
        </table>

        <h2>📝 Recommendations</h2>
        {"".join(f'''
        <div class="finding {r['priority'].lower()}">
            <strong>[{r['priority']}]</strong> {r['recommendation']}
            <br><small>Estimated Effort: {r['effort']}</small>
        </div>
        ''' for r in report.recommendations)}

        <hr>
        <p style="text-align: center; color: #666;">
            Generated by AI Gateway Red Team Module | Motilal Oswal Financial Services
        </p>
    </div>
</body>
</html>
"""
        return html
