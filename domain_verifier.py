"""
Domain registration verification using RDAP (Registration Data Access Protocol).

This module fetches and parses domain registration data from RDAP servers
to extract registration dates and verify domain age.

RDAP is the modern replacement for WHOIS, providing structured JSON data
about domain registrations.
"""

import json
import requests
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from dataclasses import dataclass


@dataclass
class DomainInfo:
    """
    Information about a domain extracted from RDAP data.

    Attributes:
        domain: The domain name (e.g., "example.com")
        registration_date: When the domain was first registered
        expiration_date: When the domain registration expires
        last_changed_date: When the domain was last modified
        last_updated_date: When RDAP database was last updated
        registrar: Name of the domain registrar
        status: List of domain status codes
        age_days: Age of the domain in days
    """
    domain: str
    registration_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    last_changed_date: Optional[datetime] = None
    last_updated_date: Optional[datetime] = None
    registrar: Optional[str] = None
    status: list = None
    age_days: Optional[int] = None

    def __post_init__(self):
        """Calculate domain age if registration date is available."""
        if self.status is None:
            self.status = []

        if self.registration_date and self.age_days is None:
            now = datetime.now(timezone.utc)
            self.age_days = (now - self.registration_date).days

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'domain': self.domain,
            'registration_date': self.registration_date.isoformat() if self.registration_date else None,
            'expiration_date': self.expiration_date.isoformat() if self.expiration_date else None,
            'last_changed_date': self.last_changed_date.isoformat() if self.last_changed_date else None,
            'last_updated_date': self.last_updated_date.isoformat() if self.last_updated_date else None,
            'registrar': self.registrar,
            'status': self.status,
            'age_days': self.age_days
        }


class DomainVerifier:
    """
    Verify domain registration information using RDAP.

    RDAP (Registration Data Access Protocol) is the modern replacement
    for WHOIS, providing structured JSON responses.
    """

    RDAP_BASE_URL = "https://www.rdap.net/domain/"

    @staticmethod
    def fetch_rdap_data(domain: str, timeout: int = 10) -> Optional[Dict[str, Any]]:
        """
        Fetch RDAP data for a domain.

        Args:
            domain: Domain name (e.g., "example.com")
            timeout: Request timeout in seconds

        Returns:
            RDAP JSON data as dictionary, or None if request fails
        """
        try:
            # Clean up domain (remove http://, https://, www., etc.)
            domain = domain.lower().strip()
            domain = domain.replace('http://', '').replace('https://', '')
            domain = domain.replace('www.', '')
            domain = domain.split('/')[0]  # Remove path if present

            # Construct RDAP URL
            url = f"{DomainVerifier.RDAP_BASE_URL}{domain}"

            print(f"[*] Fetching RDAP data for: {domain}")
            print(f"[*] URL: {url}")

            # Make GET request
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()

            # Parse JSON
            data = response.json()
            return data

        except requests.exceptions.RequestException as e:
            print(f"[!] Error fetching RDAP data: {e}")
            return None
        except json.JSONDecodeError as e:
            print(f"[!] Error parsing RDAP JSON: {e}")
            return None

    @staticmethod
    def parse_event_date(event_date_str: str) -> Optional[datetime]:
        """
        Parse ISO 8601 date string from RDAP event.

        Args:
            event_date_str: ISO 8601 date string (e.g., "2025-11-15T20:34:32Z")

        Returns:
            datetime object with timezone, or None if parsing fails
        """
        try:
            # Parse ISO 8601 format with 'Z' timezone
            if event_date_str.endswith('Z'):
                event_date_str = event_date_str[:-1] + '+00:00'

            return datetime.fromisoformat(event_date_str)
        except (ValueError, AttributeError) as e:
            print(f"[!] Error parsing date '{event_date_str}': {e}")
            return None

    @staticmethod
    def extract_domain_info(rdap_data: Dict[str, Any]) -> DomainInfo:
        """
        Extract relevant information from RDAP JSON response.

        Args:
            rdap_data: RDAP JSON data as dictionary

        Returns:
            DomainInfo object with parsed data
        """
        # Get domain name
        domain = rdap_data.get('ldhName', 'unknown')

        # Get domain status
        status = rdap_data.get('status', [])

        # Initialize date variables
        registration_date = None
        expiration_date = None
        last_changed_date = None
        last_updated_date = None

        # Parse events array
        events = rdap_data.get('events', [])
        for event in events:
            event_action = event.get('eventAction', '')
            event_date_str = event.get('eventDate', '')

            if not event_date_str:
                continue

            parsed_date = DomainVerifier.parse_event_date(event_date_str)

            if event_action == 'registration':
                registration_date = parsed_date
            elif event_action == 'expiration':
                expiration_date = parsed_date
            elif event_action == 'last changed':
                last_changed_date = parsed_date
            elif event_action == 'last update of RDAP database':
                last_updated_date = parsed_date

        # Extract registrar information
        registrar = None
        entities = rdap_data.get('entities', [])
        for entity in entities:
            roles = entity.get('roles', [])
            if 'registrar' in roles:
                # Get registrar name from vcard
                vcard_array = entity.get('vcardArray', [])
                if len(vcard_array) > 1:
                    vcard_data = vcard_array[1]
                    for field in vcard_data:
                        if field[0] == 'fn':  # Formatted name
                            registrar = field[3]
                            break
                break

        # Create DomainInfo object
        return DomainInfo(
            domain=domain,
            registration_date=registration_date,
            expiration_date=expiration_date,
            last_changed_date=last_changed_date,
            last_updated_date=last_updated_date,
            registrar=registrar,
            status=status
        )

    @staticmethod
    def verify_domain(domain: str) -> Optional[DomainInfo]:
        """
        Verify domain registration and extract information.

        This is the main method to use. It fetches RDAP data and parses it.

        Args:
            domain: Domain name to verify (e.g., "example.com")

        Returns:
            DomainInfo object with registration details, or None if failed

        Example:
            >>> verifier = DomainVerifier()
            >>> info = verifier.verify_domain("dumitru-alexandru.work")
            >>> if info:
            ...     print(f"Domain registered on: {info.registration_date}")
            ...     print(f"Domain age: {info.age_days} days")
        """
        # Fetch RDAP data
        rdap_data = DomainVerifier.fetch_rdap_data(domain)
        if not rdap_data:
            return None

        # Parse and extract information
        domain_info = DomainVerifier.extract_domain_info(rdap_data)

        return domain_info

    @staticmethod
    def print_domain_info(domain_info: DomainInfo):
        """
        Pretty print domain information.

        Args:
            domain_info: DomainInfo object to display
        """
        print("\n" + "="*60)
        print(f"Domain Information: {domain_info.domain}")
        print("="*60)

        if domain_info.registration_date:
            print(f"📅 Registration Date: {domain_info.registration_date.strftime('%Y-%m-%d %H:%M:%S UTC')}")
            print(f"⏰ Domain Age: {domain_info.age_days} days ({domain_info.age_days // 365} years)")
        else:
            print("📅 Registration Date: Not available")

        if domain_info.expiration_date:
            print(f"⌛ Expiration Date: {domain_info.expiration_date.strftime('%Y-%m-%d %H:%M:%S UTC')}")

        if domain_info.last_changed_date:
            print(f"✏️  Last Changed: {domain_info.last_changed_date.strftime('%Y-%m-%d %H:%M:%S UTC')}")

        if domain_info.registrar:
            print(f"🏢 Registrar: {domain_info.registrar}")

        if domain_info.status:
            print(f"📊 Status: {', '.join(domain_info.status)}")

        print("="*60 + "\n")


# Example usage and testing
if __name__ == "__main__":
    import sys

    # Test with example domain
    test_domain = "dumitru-alexandru.work"

    # Allow command-line argument
    if len(sys.argv) > 1:
        test_domain = sys.argv[1]

    print(f"Testing domain verification for: {test_domain}\n")

    # Verify domain
    info = DomainVerifier.verify_domain(test_domain)

    if info:
        # Print formatted output
        DomainVerifier.print_domain_info(info)

        # Print JSON output
        print("JSON Output:")
        print(json.dumps(info.to_dict(), indent=2))
    else:
        print(f"[!] Failed to verify domain: {test_domain}")
