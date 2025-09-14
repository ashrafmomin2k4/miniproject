import os
import re
import ssl
import socket
import requests
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, urljoin
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import warnings

# Suppress SSL warnings for testing
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Vulnerability weights for scoring
VULNERABILITY_WEIGHTS = {
    "ssl_issues": 20,
    "missing_security_headers": 15,
    "exposed_sensitive_files": 25,
    "sql_injection_risk": 30,
    "xss_risk": 25,
    "directory_traversal": 20,
    "information_disclosure": 10,
    "weak_authentication": 25,
    "insecure_direct_object_reference": 20,
    "server_info_disclosure": 5,
}

CLASSIFICATION_THRESHOLDS = {
    "Low Risk": (0, 29),
    "Medium Risk": (30, 59),
    "High Risk": (60, 100),
}


def classify_score(score: int) -> str:
    """Classify risk score into categories."""
    for label, (low, high) in CLASSIFICATION_THRESHOLDS.items():
        if low <= score <= high:
            return label
    return "Low Risk"


def create_session() -> requests.Session:
    """Create a requests session with proper configuration."""
    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    })
    return session


def check_ssl_security(url: str) -> Dict[str, Any]:
    """Check SSL/TLS security configuration."""
    issues = []
    score = 0
    
    try:
        parsed = urlparse(url)
        if parsed.scheme == 'https':
            # Check SSL certificate
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=parsed.hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate validity
                    import datetime
                    not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if not_after < datetime.datetime.now():
                        issues.append("SSL certificate has expired")
                        score += 10
                    
                    # Check certificate issuer
                    issuer = dict(x[0] for x in cert['issuer'])
                    if 'organizationName' in issuer and 'self-signed' in issuer['organizationName'].lower():
                        issues.append("Self-signed SSL certificate detected")
                        score += 15
        else:
            issues.append("Site is not using HTTPS")
            score += 20
            
    except Exception as e:
        issues.append(f"SSL check failed: {str(e)}")
        score += 10
    
    return {
        "issues": issues,
        "score": score,
        "category": "ssl_issues"
    }


def check_security_headers(url: str, session: requests.Session) -> Dict[str, Any]:
    """Check for missing security headers."""
    issues = []
    score = 0
    
    try:
        response = session.get(url, timeout=10, verify=False)
        headers = response.headers
        
        security_headers = {
            'Strict-Transport-Security': 'Prevents downgrade attacks',
            'X-Content-Type-Options': 'Prevents MIME type sniffing',
            'X-Frame-Options': 'Prevents clickjacking',
            'X-XSS-Protection': 'Enables XSS filtering',
            'Content-Security-Policy': 'Prevents XSS and injection attacks',
            'Referrer-Policy': 'Controls referrer information',
            'Permissions-Policy': 'Controls browser features'
        }
        
        for header, description in security_headers.items():
            if header not in headers:
                issues.append(f"Missing {header}: {description}")
                score += 2
                
    except Exception as e:
        issues.append(f"Security headers check failed: {str(e)}")
        score += 5
    
    return {
        "issues": issues,
        "score": score,
        "category": "missing_security_headers"
    }


def check_sensitive_files(url: str, session: requests.Session) -> Dict[str, Any]:
    """Check for exposed sensitive files."""
    issues = []
    score = 0
    
    sensitive_files = [
        '/.env', '/config.php', '/wp-config.php', '/.git/config',
        '/robots.txt', '/sitemap.xml', '/crossdomain.xml',
        '/phpinfo.php', '/info.php', '/test.php', '/admin.php',
        '/backup.sql', '/database.sql', '/dump.sql'
    ]
    
    for file_path in sensitive_files:
        try:
            test_url = urljoin(url, file_path)
            response = session.get(test_url, timeout=5, verify=False)
            if response.status_code == 200:
                issues.append(f"Exposed sensitive file: {file_path}")
                score += 5
        except:
            continue
    
    return {
        "issues": issues,
        "score": score,
        "category": "exposed_sensitive_files"
    }


def check_sql_injection_risk(url: str, session: requests.Session) -> Dict[str, Any]:
    """Check for potential SQL injection vulnerabilities."""
    issues = []
    score = 0
    
    # Common SQL injection payloads
    sql_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT * FROM users --",
        "1' OR '1'='1' --"
    ]
    
    # Common vulnerable parameters
    test_params = ['id', 'user', 'search', 'q', 'page', 'category']
    
    for param in test_params:
        for payload in sql_payloads:
            try:
                test_url = f"{url}?{param}={payload}"
                response = session.get(test_url, timeout=5, verify=False)
                
                # Look for SQL error patterns
                sql_errors = [
                    'mysql_fetch_array', 'ORA-01756', 'Microsoft OLE DB',
                    'SQLServer JDBC Driver', 'PostgreSQL query failed',
                    'Warning: mysql_', 'valid MySQL result', 'MySqlClient.',
                    'SQL syntax', 'mysql_num_rows', 'mysql_query'
                ]
                
                for error in sql_errors:
                    if error.lower() in response.text.lower():
                        issues.append(f"Potential SQL injection in parameter '{param}'")
                        score += 10
                        break
                        
            except:
                continue
    
    return {
        "issues": issues,
        "score": score,
        "category": "sql_injection_risk"
    }


def check_xss_risk(url: str, session: requests.Session) -> Dict[str, Any]:
    """Check for potential XSS vulnerabilities."""
    issues = []
    score = 0
    
    # XSS test payloads
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>"
    ]
    
    # Common vulnerable parameters
    test_params = ['search', 'q', 'query', 'name', 'comment', 'message']
    
    for param in test_params:
        for payload in xss_payloads:
            try:
                test_url = f"{url}?{param}={payload}"
                response = session.get(test_url, timeout=5, verify=False)
                
                # Check if payload is reflected in response
                if payload in response.text:
                    issues.append(f"Potential XSS vulnerability in parameter '{param}'")
                    score += 8
                    break
                    
            except:
                continue
    
    return {
        "issues": issues,
        "score": score,
        "category": "xss_risk"
    }


def check_directory_traversal(url: str, session: requests.Session) -> Dict[str, Any]:
    """Check for directory traversal vulnerabilities."""
    issues = []
    score = 0
    
    # Directory traversal payloads
    traversal_payloads = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    ]
    
    # Common vulnerable parameters
    test_params = ['file', 'path', 'page', 'include', 'doc']
    
    for param in test_params:
        for payload in traversal_payloads:
            try:
                test_url = f"{url}?{param}={payload}"
                response = session.get(test_url, timeout=5, verify=False)
                
                # Look for system file contents
                if 'root:' in response.text or 'bin:' in response.text or 'localhost' in response.text:
                    issues.append(f"Potential directory traversal in parameter '{param}'")
                    score += 15
                    break
                    
            except:
                continue
    
    return {
        "issues": issues,
        "score": score,
        "category": "directory_traversal"
    }


def check_server_info_disclosure(url: str, session: requests.Session) -> Dict[str, Any]:
    """Check for server information disclosure."""
    issues = []
    score = 0
    
    try:
        response = session.get(url, timeout=10, verify=False)
        headers = response.headers
        
        # Check for server information in headers
        server_header = headers.get('Server', '')
        if server_header:
            issues.append(f"Server information disclosed: {server_header}")
            score += 3
        
        # Check for technology disclosure
        tech_indicators = {
            'X-Powered-By': 'Technology stack disclosed',
            'X-AspNet-Version': 'ASP.NET version disclosed',
            'X-AspNetMvc-Version': 'ASP.NET MVC version disclosed'
        }
        
        for header, description in tech_indicators.items():
            if header in headers:
                issues.append(f"{description}: {headers[header]}")
                score += 2
                
    except Exception as e:
        issues.append(f"Server info check failed: {str(e)}")
        score += 1
    
    return {
        "issues": issues,
        "score": score,
        "category": "server_info_disclosure"
    }


def scan_website(url: str) -> Dict[str, Any]:
    """Perform comprehensive web vulnerability scan."""
    session = create_session()
    vulnerabilities = []
    total_score = 0
    
    # Run all security checks
    checks = [
        check_ssl_security,
        check_security_headers,
        check_sensitive_files,
        check_sql_injection_risk,
        check_xss_risk,
        check_directory_traversal,
        check_server_info_disclosure
    ]
    
    for check_func in checks:
        try:
            if check_func == check_ssl_security:
                result = check_func(url)
            else:
                result = check_func(url, session)
            
            if result['issues']:
                vulnerabilities.append(result)
                total_score += result['score']
                
        except Exception as e:
            vulnerabilities.append({
                "issues": [f"Check failed: {str(e)}"],
                "score": 5,
                "category": "check_error"
            })
            total_score += 5
    
    # Get basic site information
    try:
        response = session.get(url, timeout=10, verify=False)
        site_info = {
            "status_code": response.status_code,
            "content_length": len(response.content),
            "response_time": response.elapsed.total_seconds(),
            "final_url": response.url
        }
    except Exception as e:
        site_info = {
            "status_code": "Error",
            "content_length": 0,
            "response_time": 0,
            "final_url": url,
            "error": str(e)
        }
    
    classification = classify_score(total_score)
    
    return {
        "target_url": url,
        "site_info": site_info,
        "vulnerabilities": vulnerabilities,
        "total_vulnerabilities": len([v for v in vulnerabilities if v['issues']]),
        "risk_score": min(total_score, 100),  # Cap at 100
        "classification": classification,
        "scan_summary": {
            "total_checks": len(checks),
            "vulnerabilities_found": len([v for v in vulnerabilities if v['issues']]),
            "risk_level": classification
        }
    }
