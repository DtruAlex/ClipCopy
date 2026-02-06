"""
URL Verification Service for Clipboard Sync

This module provides URL verification capabilities that can be integrated
into the clipboard synchronization system. It extracts URLs from clipboard
content and checks them for security threats.

Features:
- Extract URLs from text
- Domain registration verification (check if newly registered)
- Typosquatting detection (homoglyphs, character substitution)
- Whitelist management (trusted domains)
- Real-time threat scoring
"""

import re
import json
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse
from datetime import datetime

try:
    from domain_verifier import DomainVerifier
    from typosquatting_detector import TyposquattingDetector
    HAS_VERIFICATION = True
except ImportError:
    HAS_VERIFICATION = False
    print("[!] Domain verification modules not available")


class URLVerifier:
    """
    Verify URLs for security threats.

    Checks for:
    - Newly registered domains (potential phishing)
    - Typosquatting/homograph attacks
    - Known malicious patterns
    """

    # Common legitimate domains (whitelist)
    TRUSTED_DOMAINS = {
        'google.com', 'facebook.com', 'twitter.com', 'github.com',
        'microsoft.com', 'apple.com', 'amazon.com', 'wikipedia.org',
        'youtube.com', 'linkedin.com', 'reddit.com', 'stackoverflow.com',
        'dropbox.com', 'gmail.com', 'outlook.com', 'yahoo.com'
    }

    # Domains to check for typosquatting
    PROTECTED_BRANDS = {
        'google.com', 'facebook.com', 'apple.com', 'microsoft.com',
        'amazon.com', 'paypal.com', 'github.com', 'linkedin.com',
        'twitter.com', 'instagram.com', 'netflix.com'
    }

    # URL pattern that matches Unicode characters (including Cyrillic)
    URL_PATTERN = re.compile(
        r'https?://'  # http:// or https://
        r'(?:[\w\u0400-\u04FF]'  # First character (ASCII + Cyrillic)
        r'(?:[\w\u0400-\u04FF-]{0,61}[\w\u0400-\u04FF])?\.)'  # Subdomains with Cyrillic
        r'+[a-zA-Z\u0400-\u04FF]{2,6}'  # TLD (can be Cyrillic too)
        r'(?::[0-9]{1,5})?'  # Optional port
        r'(?:[/?#][^\s]*)?',  # Path, query, fragment
        re.IGNORECASE | re.UNICODE
    )

    @staticmethod
    def extract_urls(text: str) -> List[str]:
        """
        Extract all URLs from text.

        Args:
            text: Text content (from clipboard)

        Returns:
            List of URLs found
        """
        return URLVerifier.URL_PATTERN.findall(text)

    @staticmethod
    def extract_domain(url: str) -> str:
        """
        Extract domain from URL.

        Args:
            url: Full URL

        Returns:
            Domain name (e.g., "example.com")
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
            return domain.lower()
        except:
            return ""

    @staticmethod
    def is_whitelisted(domain: str) -> bool:
        """
        Check if domain is in whitelist.

        Args:
            domain: Domain name to check

        Returns:
            True if domain is trusted
        """
        return domain.lower() in URLVerifier.TRUSTED_DOMAINS

    @staticmethod
    def check_new_domain(domain: str, threshold_days: int = 30) -> Tuple[bool, Optional[int]]:
        """
        Check if domain was registered recently.

        Args:
            domain: Domain to check
            threshold_days: Consider domains younger than this as "new"

        Returns:
            Tuple of (is_new, age_in_days)
        """
        if not HAS_VERIFICATION:
            return (False, None)

        try:
            info = DomainVerifier.verify_domain(domain)
            if info and info.age_days is not None:
                return (info.age_days < threshold_days, info.age_days)
        except:
            pass

        return (False, None)

    @staticmethod
    def check_typosquatting(domain: str) -> Dict:
        """
        Check if domain is typosquatting a known brand.

        Args:
            domain: Domain to check

        Returns:
            Dictionary with threat analysis
        """
        if not HAS_VERIFICATION:
            return {'is_typosquat': False, 'confidence': 0}

        results = []

        # Check against protected brands
        for brand in URLVerifier.PROTECTED_BRANDS:
            try:
                comparison = TyposquattingDetector.compare_domains(brand, domain)

                # Only flag if significant risk
                if comparison['risk_level'] in ['CRITICAL', 'HIGH']:
                    results.append({
                        'brand': brand,
                        'risk_level': comparison['risk_level'],
                        'risk_score': comparison['risk_score'],
                        'indicators': comparison['indicators'],
                        'has_homoglyphs': comparison['homoglyphs']['has_homoglyphs']
                    })
            except:
                continue

        if results:
            # Return highest risk match
            results.sort(key=lambda x: x['risk_score'], reverse=True)
            return {
                'is_typosquat': True,
                'matches': results,
                'top_match': results[0]
            }

        return {'is_typosquat': False, 'matches': []}

    @staticmethod
    def verify_url(url: str) -> Dict:
        """
        Comprehensive URL verification.

        Args:
            url: URL to verify

        Returns:
            Dictionary with verification results
        """
        domain = URLVerifier.extract_domain(url)

        if not domain:
            return {
                'url': url,
                'valid': False,
                'error': 'Could not extract domain'
            }

        # Check whitelist first
        if URLVerifier.is_whitelisted(domain):
            return {
                'url': url,
                'domain': domain,
                'safe': True,
                'reason': 'Whitelisted domain',
                'threat_score': 0
            }

        threats = []
        threat_score = 0

        # Check if newly registered
        is_new, age_days = URLVerifier.check_new_domain(domain, threshold_days=90)
        if is_new and age_days is not None:
            threats.append(f"Recently registered ({age_days} days old)")
            if age_days < 7:
                threat_score += 40
            elif age_days < 30:
                threat_score += 25
            else:
                threat_score += 15

        # Check for typosquatting
        typosquat_result = URLVerifier.check_typosquatting(domain)
        if typosquat_result['is_typosquat']:
            top_match = typosquat_result['top_match']
            threats.append(
                f"Looks like {top_match['brand']} "
                f"(risk: {top_match['risk_level']})"
            )
            threat_score += top_match['risk_score']

            if top_match['has_homoglyphs']:
                threats.append("Contains homoglyphs (lookalike characters)")
                threat_score += 30

        # Determine overall safety
        if threat_score >= 80:
            safety_level = 'DANGEROUS'
            safe = False
        elif threat_score >= 50:
            safety_level = 'SUSPICIOUS'
            safe = False
        elif threat_score >= 30:
            safety_level = 'QUESTIONABLE'
            safe = True
        else:
            safety_level = 'SAFE'
            safe = True

        return {
            'url': url,
            'domain': domain,
            'safe': safe,
            'safety_level': safety_level,
            'threat_score': threat_score,
            'threats': threats,
            'age_days': age_days,
            'typosquat_analysis': typosquat_result if typosquat_result['is_typosquat'] else None
        }

    @staticmethod
    def verify_text(text: str) -> Dict:
        """
        Scan text for URLs and verify them.

        Args:
            text: Text content (from clipboard)

        Returns:
            Dictionary with all URLs and their verification results
        """
        urls = URLVerifier.extract_urls(text)

        if not urls:
            return {
                'has_urls': False,
                'url_count': 0,
                'urls': []
            }

        results = []
        max_threat_score = 0

        for url in urls:
            verification = URLVerifier.verify_url(url)
            results.append(verification)
            if verification.get('threat_score', 0) > max_threat_score:
                max_threat_score = verification['threat_score']

        return {
            'has_urls': True,
            'url_count': len(urls),
            'urls': results,
            'max_threat_score': max_threat_score,
            'has_threats': max_threat_score >= 30
        }


def format_verification_warning(verification: Dict) -> str:
    """
    Format a human-readable warning message.

    Args:
        verification: Verification result from verify_text()

    Returns:
        Formatted warning message
    """
    if not verification['has_urls']:
        return ""

    if not verification['has_threats']:
        return ""

    warnings = []
    warnings.append("⚠️  URL SECURITY ALERT ⚠️")
    warnings.append("=" * 60)

    for url_result in verification['urls']:
        if not url_result.get('safe', True):
            warnings.append(f"\n🔴 {url_result['url']}")
            warnings.append(f"   Domain: {url_result['domain']}")
            warnings.append(f"   Risk: {url_result['safety_level']} "
                          f"(Score: {url_result['threat_score']}/100)")

            if url_result.get('threats'):
                warnings.append("   Threats detected:")
                for threat in url_result['threats']:
                    warnings.append(f"   • {threat}")

    warnings.append("\n" + "=" * 60)
    warnings.append("⚠️  Verify the URL before clicking! ⚠️")

    return "\n".join(warnings)


if __name__ == "__main__":
    # Test the URL verifier
    print("="*70)
    print(" URL Verification System - Tests")
    print("="*70)

    # Test 1: Safe URL
    print("\n[Test 1] Safe URL:")
    result = URLVerifier.verify_url("https://google.com/search?q=test")
    print(f"Domain: {result['domain']}")
    print(f"Safe: {result['safe']}")
    print(f"Reason: {result.get('reason', 'N/A')}")

    # Test 2: Potential typosquat
    print("\n[Test 2] Typosquatting check:")
    # Create a suspicious domain (with Cyrillic 'o')
    result = URLVerifier.verify_url("https://g00gle.com/login")
    print(f"Domain: {result['domain']}")
    print(f"Safe: {result['safe']}")
    print(f"Safety Level: {result['safety_level']}")
    print(f"Threat Score: {result['threat_score']}")
    if result.get('threats'):
        print("Threats:")
        for threat in result['threats']:
            print(f"  • {threat}")

    # Test 3: Text with multiple URLs
    print("\n[Test 3] Text scanning:")
    text = """
    Check out https://google.com for search
    And visit https://gооgle.com for phishing (Cyrillic o)
    """
    result = URLVerifier.verify_text(text)
    print(f"URLs found: {result['url_count']}")
    print(f"Has threats: {result['has_threats']}")
    print(f"Max threat score: {result['max_threat_score']}")

    # Print warning
    warning = format_verification_warning(result)
    if warning:
        print("\n" + warning)
