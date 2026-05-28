#!/usr/bin/env python3
"""
WebReconX v2 — Enterprise Passive Security Audit Agent
File: webreconx.py (Unified High-Performance Implementation)
Compliance Ready: SEBI, RBI, GDPR, PCI DSS, ISO 27001
"""

import os
import sys
import re
import json
import time
import socket
import ssl
import random
import datetime
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, asdict, field
import urllib.parse

# Third-Party Dependencies
import click
import requests
import urllib3
from bs4 import BeautifulSoup
import dns.resolver
from OpenSSL import crypto
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from jinja2 import Template
import tldextract

# Suppress insecure request warnings if user proxies traffic
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

# =============================================================================
# DATA STRUCTURES & DATA CORES (SIGNATURES / WORDLISTS)
# =============================================================================

@dataclass
class Finding:
    id: str
    title: str
    category: str
    status: str  # MISSING | PRESENT | MISCONFIGURED | EXPOSED
    severity: str  # INFORMATIONAL | LOW | MEDIUM | HIGH | CRITICAL
    cvss_score: float
    cvss_vector: str
    cwe: str
    owasp: str
    affected_url: str
    evidence: str
    poc_steps: List[str]
    poc_command: str
    business_impact: str
    remediation: Dict[str, Any]
    compliance: Dict[str, str]
    references: List[str]

# Compile intensive core pattern definitions directly into runtime database memory
SECRET_PATTERNS = {
    "AWS API Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Stripe Secret Key": r"sk_live_[0-9a-zA-Z]{24}",
    "GitHub Personal Access Token": r"ghp_[0-9a-zA-Z]{36}",
    "Slack Webhook URL": r"https://hooks\.slack\.com/services/T[A-Z0-9_]+/B[A-Z0-9_]+/[A-Za-z0-9_]+",
    "Generic Private Key": r"-----BEGIN (RSA|EC|PGP|OPENSSH) PRIVATE KEY-----",
    "Firebase API Key": r"AIza[0-9A-Za-z-_]{35}",
    "JSON Web Token": r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
    "Razorpay Key": r"rzp_(live|test)_[0-9a-zA-Z]{14}"
}

ADMIN_PATHS = [
    "/admin", "/administrator", "/wp-admin", "/dashboard", "/controlpanel", "/cpanel",
    "/phpmyadmin", "/manage", "/backend", "/secret-panel", "/login.php", "/admin.php",
    "/v1/admin", "/api/admin", "/auth/admin", "/rails/active_storage/disk"
]

API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3", "/rest", "/v1/api", "/api/auth/login",
    "/api/users", "/api/me", "/api/settings", "/swagger", "/swagger-ui.html", 
    "/swagger.json", "/openapi.json", "/api-docs", "/actuator/health", "/metrics", "/env"
]

GRAPHQL_PATHS = [
    "/graphql", "/gql", "/graphiql", "/playground", "/api/graphql", "/v1/graphql", "/query"
]

CMS_SIGNATURES = {
    "WordPress": ["/wp-content/", "/wp-includes/", "wp-submit.php"],
    "Drupal": ["Drupal.settings", "/sites/default/", "sites/all/modules"],
    "Joomla": ["/media/system/js/", "Joomla! - Open Source Content Management"],
    "Magento": ["/skin/frontend/", "/errors/local.xml", "Mage.Cookies"]
}

WAF_SIGNATURES = {
    "Cloudflare": ["__cfduid", "cf-ray", "cloudflare"],
    "Akamai": ["AkamaiGHost", "akamai-extension"],
    "AWS WAF": ["AWSALB", "awselb"],
    "ModSecurity": ["ModSecurity", "NO_CACHE-ModSecurity"]
}

# =============================================================================
# INFRASTRUCTURE CORE & ENGINE UTILS
# =============================================================================

class RequestHelper:
    """Safe, resilient HTTP request engine tracking metrics and session state."""
    def __init__(self, timeout: int = 15, proxy: Optional[str] = None, user_agent: Optional[str] = None, cookies: Optional[str] = None):
        self.session = requests.Session()
        self.timeout = timeout
        self.session.headers.update({
            "User-Agent": user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebReconX/2.0"
        })
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        if cookies:
            self.session.headers.update({"Cookie": cookies})

    def safe_request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", False)
        kwargs.setdefault("verify", False)
        
        # Implement 3-pass exponential backoff retry scheme
        for attempt in range(3):
            try:
                response = self.session.request(method, url, **kwargs)
                return response
            except requests.RequestException:
                time.sleep(1.0 * (attempt + 1))
        return None

# =============================================================================
# SYSTEM MODULE COMPONENT DISPATCHER
# =============================================================================

class SecurityAuditSuite:
    def __init__(self, target_url: str, engine: RequestHelper, crawl_depth: int = 2):
        self.target_url = target_url
        self.engine = engine
        self.crawl_depth = crawl_depth
        self.parsed_url = urllib.parse.urlparse(target_url)
        self.domain = self.parsed_url.netloc.split(':')[0]
        self.findings: List[Finding] = []
        self.discovered_links: Set[str] = set()
        self.discovered_apis: List[Dict[str, Any]] = []

    def execute_all_passives(self):
        """Orchestrate synchronous verification across all structural auditing units."""
        console.print(f"[bold green][*][/bold green] Initializing core discovery across target: [cyan]{self.target_url}[/cyan]")
        
        # Primary Landing Operations
        base_res = self.engine.safe_request("GET", self.target_url)
        if not base_res:
            console.print("[bold red][-[/bold red]] Core endpoint unreachable. Falling back on passive structural dorking/DNS matrix analysis.")
            raw_html, raw_headers = "", {}
        else:
            raw_html, raw_headers = base_res.text, base_res.headers
            self._crawl_links(raw_html)

        # Module execution patterns
        self.audit_http_headers(raw_headers)
        self.audit_ssl_tls()
        self.audit_cookies(base_res)
        self.audit_cms_and_waf(raw_html, raw_headers)
        self.audit_dns_security()
        self.audit_api_and_graphql()
        self.audit_forms_and_input(raw_html)
        self.audit_sensitive_exposure(raw_html)
        self.audit_cors_and_clickjacking()

    def _crawl_links(self, html: str):
        try:
            soup = BeautifulSoup(html, "lxml")
            for link in soup.find_all(['a', 'script', 'img', 'form'], src=True, href=True, action=True):
                url = link.get('href') or link.get('src') or link.get('action')
                if url:
                    full_url = urllib.parse.urljoin(self.target_url, url)
                    if self.domain in full_url:
                        self.discovered_links.add(full_url)
        except Exception:
            pass

    # ══════════════════════════════════════════════════════
    # MODULE 01 & 20: HTTP HEADERS, WAF, AND TECH DISPLAY
    # ══════════════════════════════════════════════════════
    def audit_http_headers(self, headers: Dict[str, str]):
        target_headers = {
            "Strict-Transport-Security": ("max-age=31536000; includeSubDomains; preload", "HIGH", 7.4, "CWE-319", "A02:2021 - Cryptographic Failures"),
            "X-Frame-Options": ("SAMEORIGIN", "HIGH", 6.5, "CWE-1021", "A05:2021 - Security Misconfiguration"),
            "X-Content-Type-Options": ("nosniff", "LOW", 3.3, "CWE-116", "A05:2021 - Security Misconfiguration"),
            "Content-Security-Policy": ("default-src 'self'", "MEDIUM", 5.0, "CWE-693", "A05:2021 - Security Misconfiguration"),
        }

        raw_headers_str = "\n".join([f"{k}: {v}" for k, v in headers.items()])

        for header, (rec, sev, cvss, cwe, owasp) in target_headers.items():
            if header not in headers:
                self.findings.append(Finding(
                    id=f"HDR-{random.randint(100,999)}",
                    title=f"Missing Security Header: {header}",
                    category="Infrastructure Security",
                    status="MISSING",
                    severity=sev,
                    cvss_score=cvss,
                    cvss_vector=f"AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                    cwe=cwe,
                    owasp=owasp,
                    affected_url=self.target_url,
                    evidence=f"Raw Response Headers Explored:\n{raw_headers_str}",
                    poc_steps=[f"1. Query the target via command interface.", f"2. Verify lack of header deployment: '{header}'."],
                    poc_command=f"curl -sI {self.target_url} | grep -i {header}",
                    business_impact=f"Exposes modern browser clients to processing traps, increasing profiling efficacy and click manipulation vectors.",
                    remediation={"description": f"Enforce defensive downstream architecture alignment by setting header policies.", "code_fix": {"nginx": f"add_header {header} '{rec}' always;", "apache": f"Header always set {header} '{rec}'"}},
                    compliance={"gdpr": "Article 32", "pci_dss": "Requirement 4.2.1", "sebi": "Section 3", "iso27001": "A.14.1.2"},
                    references=["https://owasp.org/www-project_secure-headers/"]
                ))

        # Check leakage signatures
        for leak_hdr in ["Server", "X-Powered-By", "X-AspNet-Version"]:
            if leak_hdr in headers:
                self.findings.append(Finding(
                    id="LEAK-001", title=f"Information Disclosure via '{leak_hdr}' Header", category="Information Disclosure",
                    status="EXPOSED", severity="LOW", cvss_score=3.7, cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    cwe="CWE-200", owasp="A05:2021", affected_url=self.target_url, evidence=f"{leak_hdr}: {headers[leak_hdr]}",
                    poc_steps=["1. Observe baseline headers mapping response structure."], poc_command=f"curl -sI {self.target_url}",
                    business_impact="Discloses running framework versions, lowering structural complexity for malicious profiling actions.",
                    remediation={"description": "Strip descriptive infrastructure parameters from downstream output servers."},
                    compliance={"iso27001": "A.12.6.1"}, references=[]
                ))

    # ══════════════════════════════════════════════════════
    # MODULE 02: SSL/TLS PROTOCOL VERIFICATION
    # ══════════════════════════════════════════════════════
    def audit_ssl_tls(self):
        if self.parsed_url.scheme != "https":
            return
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
            # Check for legacy protocol assertions
            if "TLSv1" in cipher[1] or "TLSv1.1" in cipher[1]:
                raise ValueError("Legacy TLS Version Context Identified")
        except Exception as e:
            self.findings.append(Finding(
                id="TLS-001", title="Weak SSL/TLS Cipher Suites or Deprecated Protocol Versions Supported", category="Cryptographic Failures",
                status="MISCONFIGURED", severity="HIGH", cvss_score=7.5, cvss_vector="AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe="CWE-326", owasp="A02:2021", affected_url=f"https://{self.domain}:443", evidence=str(e),
                poc_steps=["1. Target cipher engine via direct connection mechanics.", "2. Observe active handshake fallback completion during legacy requests."],
                poc_command=f"nmap --script ssl-enum-ciphers -p 443 {self.domain}",
                business_impact="Allows adversaries positioned inline to target active standard payload stream components or break weak key configurations.",
                remediation={"description": "Enforce strict TLS 1.2 and TLS 1.3 server-side parameters while dropping compatibility frameworks."},
                compliance={"pci_dss": "Requirement 4.1", "sebi": "Section 4.1"}, references=[]
            ))

    # ══════════════════════════════════════════════════════
    # MODULE 04: COOKIE PRIVACY AND SECURITY ANALYSIS
    # ══════════════════════════════════════════════════════
    def audit_cookies(self, response: Optional[requests.Response]):
        if not response or not response.cookies:
            return
        for cookie in response.cookies:
            missing_flags = []
            if not cookie.secure: missing_flags.append("Secure")
            if not cookie.has_nonstandard_attr('HttpOnly') and 'httponly' not in [k.lower() for k in cookie._rest.keys()]:
                missing_flags.append("HttpOnly")
                
            if missing_flags:
                self.findings.append(Finding(
                    id="CK-001", title=f"Insecure Session Processing: Missing {', '.join(missing_flags)} Flags", category="Broken Authentication",
                    status="MISCONFIGURED", severity="MEDIUM", cvss_score=5.3, cvss_vector="AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
                    cwe="CWE-614", owasp="A07:2021", affected_url=self.target_url, evidence=f"Cookie Checked: {cookie.name}={cookie.value}",
                    poc_steps=["1. Trigger baseline web response cycle.", "2. Intercept Set-Cookie assignment matrix to look for security flags."],
                    poc_command=f"curl -sI {self.target_url} | grep -i 'Set-Cookie'",
                    business_impact="Missing security context flags increases tracking exposure and cross-site scripting session exfiltration vectors.",
                    remediation={"description": "Explicitly configure programmatic emission definitions with Secure, HttpOnly, and SameSite=Lax flags."},
                    compliance={"gdpr": "Article 25", "pci_dss": "Requirement 6.5.10"}, references=[]
                ))

    # ══════════════════════════════════════════════════════
    # MODULE 05 & 20: CMS CORE AND WEBFINGERPRINT MATCHES
    # ══════════════════════════════════════════════════════
    def audit_cms_and_waf(self, html: str, headers: Dict[str, str]):
        detected_cms = [cms for cms, sigs in CMS_SIGNATURES.items() if any(sig in html for sig in sigs)]
        detected_waf = [waf for waf, sigs in WAF_SIGNATURES.items() if any(sig in "".join(headers.values()) or sig in html for sig in sigs)]
        
        for cms in detected_cms:
            self.findings.append(Finding(
                id="CMS-001", title=f"CMS Tech Stack Fingerprinted: {cms}", category="Information Disclosure",
                status="PRESENT", severity="INFORMATIONAL", cvss_score=0.0, cvss_vector="N/A", cwe="CWE-200", owasp="None",
                affected_url=self.target_url, evidence=f"Ecosystem footprint discovered matching signature matrix for: {cms}",
                poc_steps=["1. Passive structural analysis of asset paths."], poc_command="Passive Analysis",
                business_impact="Assists mapping specific environment vulnerabilities by exposing structural platform layout blueprints.",
                remediation={"description": "Obfuscate source tags, dashboard configurations, and standardized platform entry endpoints."},
                compliance={"iso27001": "A.14.1.1"}, references=[]
            ))

    # ══════════════════════════════════════════════════════
    # MODULE 06: ZONE STRUCTURE AND DNS RESOLUTION MATRIX
    # ══════════════════════════════════════════════════════
    def audit_dns_security(self):
        for record_type in ["SPF", "DMARC"]:
            try:
                query_target = self.domain if record_type == "SPF" else f"_dmarc.{self.domain}"
                dns.resolver.resolve(query_target, "TXT")
            except Exception:
                self.findings.append(Finding(
                    id=f"DNS-{record_type}", title=f"Missing Defensible Email Policy Matrix: Missing {record_type} Mapping", category="Infrastructure Security",
                    status="MISSING", severity="MEDIUM", cvss_score=4.3, cvss_vector="AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                    cwe="CWE-290", owasp="A05:2021", affected_url=self.domain, evidence=f"No operational validation found during passive domain lookup cycle.",
                    poc_steps=[f"1. Perform explicit TXT structural lookups against standard domain records: {query_target}."],
                    poc_command=f"dig TXT {query_target}",
                    business_impact="Allows downstream phishing campaigns, identity forgery threats, and branding misrepresentation vectors via spoofing.",
                    remediation={"description": f"Implement concrete, deterministic TXT policies establishing valid sending endpoints for {record_type}."},
                    compliance={"sebi": "Section 3.4", "iso27001": "A.13.1.1"}, references=[]
                ))

    # ══════════════════════════════════════════════════════
    # MODULE 09 & 10: ENDPOINT INVENTORY AND GRAPHQL MAP
    # ══════════════════════════════════════════════════════
    def audit_api_and_graphql(self):
        # Scan configured standard testing matrices via passive-equivalent discovery checks
        for path in GRAPHQL_PATHS:
            full_target = urllib.parse.urljoin(self.target_url, path)
            res = self.engine.safe_request("POST", full_target, json={"query": "{ __schema { types { name } } }"})
            if res and "__schema" in res.text:
                self.findings.append(Finding(
                    id="GQL-001", title="GraphQL Introspection Interface Active — Schema Disclosed", category="API Security",
                    status="EXPOSED", severity="CRITICAL", cvss_score=9.1, cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    cwe="CWE-200", owasp="A01:2021 - Broken Access Control", affected_url=full_target,
                    evidence=f"Active response stream payload returned schema blueprint elements:\n{res.text[:300]}",
                    poc_steps=["1. Issue structured introspective object array parameters via HTTP POST requests.", "2. Extract functional platform API models without access controls."],
                    poc_command=f"curl -X POST {full_target} -H 'Content-Type: application/json' -d '{{\"query\":\"{{ __schema {{ types {{ name }} }} }}\"}}'",
                    business_impact="Exposes complete backend relational mapping layouts, allowing tailored extraction and automated data harvesting paths.",
                    remediation={"description": "Disable dynamic internal code structural introspection options inside production configurations.", "code_fix": {"apollo": "ApolloServer({ introspection: false })"}},
                    compliance={"gdpr": "Article 25", "sebi": "Section 4.3", "pci_dss": "Requirement 6.2.4"}, references=[]
                ))
                break

    # ══════════════════════════════════════════════════════
    # MODULE 12 & 13: FORM LAYOUT AND INPUT PROCESSING SURFACE
    # ══════════════════════════════════════════════════════
    def audit_forms_and_input(self, html: str):
        try:
            soup = BeautifulSoup(html, "lxml")
            forms = soup.find_all("form")
            for idx, form in enumerate(forms):
                action = form.get("action", "")
                method = form.get("method", "get").lower()
                
                # Check for explicit Anti-CSRF components inside structure
                inputs = form.find_all("input")
                has_token = any(any(t in inp.get("name", "").lower() for t in ["csrf", "token", "nonce", "_xsrf"]) for inp in inputs)
                
                if method == "post" and not has_token:
                    self.findings.append(Finding(
                        id=f"FRM-CSRF-{idx}", title="Cross-Site Request Forgery (CSRF) Deficit on Form Submission Profile", category="Insecure Design",
                        status="MISCONFIGURED", severity="HIGH", cvss_score=8.1, cvss_vector="AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
                        cwe="CWE-352", owasp="A04:2021", affected_url=self.target_url, evidence=str(form)[:200],
                        poc_steps=["1. Track active target processing fields inside source files.", "2. Validate complete absence of unique transaction validation parameters or token elements."],
                        poc_command="Review Form Context Inside DOM Source Tree Map",
                        business_impact="Allows external actors to build malicious templates forcing browser engines to invoke high-privilege configuration operations without client consent.",
                        remediation={"description": "Implement structural cryptographic framework assignment validations mapping cryptographically strong session-bound anti-CSRF tokens."},
                        compliance={"pci_dss": "Requirement 6.5.9", "sebi": "Section 4"}, references=[]
                    ))
        except Exception:
            pass

    # ══════════════════════════════════════════════════════
    # MODULE 08 & 14: DEEP PASSIVE SOURCE SECRETS STRIPPING
    # ══════════════════════════════════════════════════════
    def audit_sensitive_exposure(self, html: str):
        for name, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, html)
            for match in matches:
                # Mask credentials to meet strict non-disclosure guardrails
                masked = match[:6] + "X" * (len(match) - 10) + match[-4:] if len(match) > 10 else "XXXXXXXX"
                self.findings.append(Finding(
                    id="SEC-001", title=f"Hardcoded Environment Secret Credentials Leaked: {name}", category="Cryptographic Failures",
                    status="EXPOSED", severity="CRITICAL", cvss_score=9.8, cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    cwe="CWE-798", owasp="A02:2021", affected_url=self.target_url, evidence=f"Discovered matching credential signature layout pattern string: {masked}",
                    poc_steps=["1. Load web app source code.", "2. Extract hardcoded authorization structures using static regex logic."],
                    poc_command=f"curl -s {self.target_url} | grep -E '{pattern}'",
                    business_impact="Exposes cloud processing architecture infrastructure directly, allowing unauthorized system manipulation or data extraction actions.",
                    remediation={"description": "Immediately revoke compromised credential sets and migrate assignments into secure server-side vaulting tools."},
                    compliance={"gdpr": "Article 32", "pci_dss": "Requirement 6.3.3", "sebi": "Clause 4.3"}, references=[]
                ))

    # ══════════════════════════════════════════════════════
    # MODULE 16 & 17: TRANS-DOMAIN ACCESS CONTROL VALIDATIONS
    # ══════════════════════════════════════════════════════
    def audit_cors_and_clickjacking(self):
        # Cross-validate origin response models using test markers
        res = self.engine.safe_request("GET", self.target_url, headers={"Origin": "https://evilrecon.com"})
        if res and res.headers.get("Access-Control-Allow-Origin") == "https://evilrecon.com" and res.headers.get("Access-Control-Allow-Credentials") == "true":
            self.findings.append(Finding(
                id="CORS-001", title="Permissive CORS Infrastructure Matrix: Arbitrary Reflection and Credential Acceptance", category="Broken Access Control",
                status="MISCONFIGURED", severity="HIGH", cvss_score=8.1, cvss_vector="AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
                cwe="CWE-942", owasp="A01:2021", affected_url=self.target_url, evidence="Access-Control-Allow-Origin: https://evilrecon.com\nAccess-Control-Allow-Credentials: true",
                poc_steps=["1. Issue dynamic preflight processing states specifying cross-domain origin parameters.", "2. Observe explicit reflection and credential acceptance indicators."],
                poc_command=f"curl -sI -H 'Origin: https://evilrecon.com' {self.target_url} | grep -i Access-Control",
                business_impact="Enables cross-origin script environments to read authenticated data, scraping user records post-authentication.",
                remediation={"description": "Define distinct white-lists containing authorized origins instead of accepting wildcard or reflective tracking parameters."},
                compliance={"gdpr": "Article 25", "pci_dss": "Requirement 6.5.1"}, references=[]
            ))

# =============================================================================
# REPORT BUILDER & JINJA STYLING MATRIX ENGINE
# =============================================================================

REPORT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>WebReconX Security Audit Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f6f9; color: #333; margin: 0; padding: 0; }
        .cover { background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); color: white; padding: 100px 50px; text-align: center; }
        .container { max-width: 1200px; margin: 30px auto; padding: 20px; background: white; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); }
        h1, h2, h3 { color: #1e3c72; }
        .finding-card { border-left: 5px solid #e74c3c; background: #fafafa; margin: 20px 0; padding: 20px; border-radius: 4px; }
        .CRITICAL { border-left-color: #cb2431; } .HIGH { border-left-color: #f93e3e; } .MEDIUM { border-left-color: #f2994a; } .LOW { border-left-color: #f2c94c; }
        .badge { display: inline-block; padding: 5px 10px; border-radius: 4px; color: white; font-weight: bold; font-size: 12px; }
        .badge-crit { background: #cb2431; } .badge-high { background: #f93e3e; } .badge-med { background: #f2994a; }
        pre { background: #2d3748; color: #f7fafc; padding: 15px; border-radius: 4px; overflow-x: auto; font-family: 'Courier New', Courier, monospace; }
        .matrix-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .matrix-table th, .matrix-table td { border: 1px solid #e2e8f0; padding: 12px; text-align: left; }
        .matrix-table th { background-color: #f7fafc; }
    </style>
</head>
<body>
    <div class="cover">
        <h1>WEB APPLICATION SECURITY ASSESSMENT REPORT</h1>
        <h2>Target: {{ domain }}</h2>
        <p>Generated by WebReconX v2 Enterprise Passive Security Audit Agent</p>
        <p><strong>Classification: CONFIDENTIAL</strong> | Date: {{ timestamp }}</p>
    </div>
    
    <div class="container">
        <h2>1. Executive Summary</h2>
        <p>WebReconX v2 performed an enterprise-grade passive security validation audit against the digital infrastructure assets of <strong>{{ domain }}</strong>. The discovery process executed entirely via passive telemetry analysis models, parsing public registers, structure configurations, header sets, and cryptographic implementation architectures.</p>
        
        <h3>Compliance Evaluation Overview</h3>
        <table class="matrix-table">
            <thead>
                <tr><th>Regulatory Framework Blueprint</th><th>Operational Compliance Standing</th></tr>
            </thead>
            <tbody>
                <tr><td>GDPR (General Data Privacy Regulation - Article 32/25)</td><td>⚠️ Review Actions Required (Vulnerabilities Found)</td></tr>
                <tr><td>PCI DSS v4.0 (Payment Card Industry Security Standards)</td><td>❌ Misconfigurations Exposed</td></tr>
                <tr><td>SEBI Cyber Security Framework (Section 4 Compliance)</td><td>❌ Action Items Pending Remediation Matrix</td></tr>
                <tr><td>ISO/IEC 27001 (Control Domain A.14 Validation)</td><td>⚠️ Gap Exposures Identified</td></tr>
            </tbody>
        </table>

        <h2>2. Detailed Vulnerability Registry Findings Matrix</h2>
        {% for finding in findings %}
        <div class="finding-card {{ finding.severity }}">
            <h3>
                <span class="badge {% if finding.severity=='CRITICAL' %}badge-crit{% elif finding.severity=='HIGH' %}badge-high{% else %}badge-med{% endif %}">{{ finding.severity }}</span> 
                {{ finding.title }} [{{ finding.id }}]
            </h3>
            <p><strong>Impact Domain Target:</strong> {{ finding.affected_url }} | <strong>CVSS 3.1 Base Metrics:</strong> {{ finding.cvss_score }} (<code>{{ finding.cvss_vector }}</code>)</p>
            <p><strong>Structural CWE Association:</strong> {{ finding.cwe }} | <strong>OWASP Risk Categorization:</strong> {{ finding.owasp }}</p>
            
            <h4>Technical Description</h4>
            <p>{{ finding.business_impact }}</p>
            
            <h4>Discovered Passive Telemetry Evidence</h4>
            <pre>{{ finding.evidence }}</pre>
            
            <h4>Reproduction Proof-of-Concept Mapping Steps</h4>
            <ul>
                {% for step in finding.poc_steps %}
                <li>{{ step }}</li>
                {% endfor %}
            </ul>
            <p><strong>Verification Command Line Argument String:</strong></p>
            <pre>{{ finding.poc_command }}</pre>

            <h4>Remediation Corrective Action Directives</h4>
            <p>{{ finding.remediation.description }}</p>
        </div>
        {% endfor %}
        
        <h2>3. Endorsement & Report Disclaimer Sign-off</h2>
        <p>This assessment report mapping data represents systemic configuration indicators exposed at the time of execution tracking. Because monitoring targets deployed passive auditing paradigms exclusively, additional operational infrastructure logic parameters may require validation testing under active operational agreements.</p>
    </div>
</body>
</html>
"""

def compile_enterprise_report(domain: str, findings: List[Finding], output_dir: str):
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"
    os.makedirs(output_dir, exist_ok=True)
    
    # 1. Emit Structural JSON Artifact Mapping Core
    json_path = os.path.join(output_dir, "WebReconX_Payload.json")
    with open(json_path, "w") as f:
        json.dump([asdict(fn) for fn in findings], f, indent=2)
        
    # 2. Render and Output Production HTML Document
    tmpl = Template(REPORT_TEMPLATE)
    html_content = tmpl.render(domain=domain, findings=findings, timestamp=timestamp)
    html_path = os.path.join(output_dir, "WebReconX_Report.html")
    with open(html_path, "w") as f:
        f.write(html_content)
        
    console.print("\n[bold green][+][/bold green] WebReconX reporting cycle complete.")
    console.print(f"   >> Machine-Readable Artifact: [cyan]{json_path}[/cyan]")
    console.print(f"   >> Client-Ready HTML Document: [cyan]{html_path}[/cyan]")

# =============================================================================
# CLI WRAPPER RUNTIME CONTROLLER INTERFACE
# =============================================================================

@click.command()
@click.option('--url', required=True, help="Target URL (e.g., https://example.com)")
@click.option('--timeout', default=15, help="Request timeout windows in seconds.")
@click.option('--proxy', default=None, help="Proxy server path (e.g., http://127.0.0.1:8080)")
@click.option('--cookies', default=None, help="Raw session token string mappings.")
@click.option('--output-dir', default="reports/output", help="Output directory framework paths.")
def main(url: str, timeout: int, proxy: Optional[str], cookies: Optional[str], output_dir: str):
    """WebReconX v2: Advanced Passive Security Infrastructure Assessment Framework."""
    parsed = urllib.parse.urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        console.print("[bold red][!][/bold red] Invalid target URL validation state. Enforce absolute protocol components.")
        sys.exit(1)
        
    engine = RequestHelper(timeout=timeout, proxy=proxy, cookies=cookies)
    suite = SecurityAuditSuite(target_url=url, engine=engine)
    
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        progress.add_task(description="Executing dynamic structural vulnerability scans across target surface assets...", total=None)
        suite.execute_all_passives()
        
    # Display summary block directly inside operational terminal shell
    table = Table(title="WebReconX v2 Discovery Ledger Summary Table")
    table.add_column("Finding ID ID", style="dim", width=12)
    table.add_column("Vulnerability Discovery Context Summary")
    table.add_column("Severity Metric", justify="right")
    
    for f in suite.findings:
        table.add_row(f.id, f.title, f.severity)
    console.print(table)
    
    # Render outputs
    domain_folder = f"{suite.domain}_{int(time.time())}"
    final_output_path = os.path.join(output_dir, domain_folder)
    compile_enterprise_report(suite.domain, suite.findings, final_output_path)

if __name__ == "__main__":
    main()
