"""
Typosquatting Detection System

Detects various types of domain impersonation:
1. Character substitution (l → I, 0 → O)
2. Homoglyphs (visually similar characters)
3. Cyrillic lookalikes (а → a, е → e, о → o)
4. Common typos (missing letters, swapped letters)
5. Additional/removed characters

This is useful for:
- Brand protection
- Phishing detection
- Security research
"""

import unicodedata
from typing import List, Set, Dict, Tuple
from itertools import combinations
from domain_verifier import DomainVerifier


class TyposquattingDetector:
    """
    Detect typosquatting domains using various techniques.

    Typosquatting is when attackers register domains that look similar
    to legitimate domains to trick users (e.g., "gooogle.com" vs "google.com").
    """

    # Common character substitutions (Latin lookalikes)
    SUBSTITUTIONS = {
        'a': ['а', '@', '4'],           # Latin 'a' vs Cyrillic 'а'
        'e': ['е', '3'],                # Latin 'e' vs Cyrillic 'е'
        'i': ['l', '1', 'ı', 'í', 'ì'], # Latin 'i' vs 'l', Turkish 'ı'
        'l': ['i', '1', 'I'],           # Latin 'l' vs 'i', 'I'
        'o': ['о', '0'],                # Latin 'o' vs Cyrillic 'о', zero
        'u': ['υ', 'ü', 'ù'],           # Latin 'u' vs Greek 'υ'
        'c': ['с', 'ç'],                # Latin 'c' vs Cyrillic 'с'
        'p': ['р'],                     # Latin 'p' vs Cyrillic 'р'
        'h': ['һ'],                     # Latin 'h' vs Cyrillic 'һ'
        'x': ['х'],                     # Latin 'x' vs Cyrillic 'х'
        'y': ['у'],                     # Latin 'y' vs Cyrillic 'у'
        's': ['ѕ', '$', '5'],           # Latin 's' vs Cyrillic 'ѕ'
        't': ['τ'],                     # Latin 't' vs Greek 'τ'
        'n': ['ո'],                     # Latin 'n' vs Armenian 'ո'
        'm': ['м'],                     # Latin 'm' vs Cyrillic 'м'
        'b': ['ь', 'б'],                # Latin 'b' vs Cyrillic soft sign
        'd': ['ԁ'],                     # Latin 'd' vs Cyrillic 'ԁ'
        'g': ['ց', '9'],                # Latin 'g' vs Armenian 'ց'
    }

    # Cyrillic characters that look like Latin
    CYRILLIC_LOOKALIKES = {
        'а': 'a',  # Cyrillic а → Latin a
        'е': 'e',  # Cyrillic е → Latin e
        'о': 'o',  # Cyrillic о → Latin o
        'р': 'p',  # Cyrillic р → Latin p
        'с': 'c',  # Cyrillic с → Latin c
        'у': 'y',  # Cyrillic у → Latin y
        'х': 'x',  # Cyrillic х → Latin x
        'і': 'i',  # Cyrillic і → Latin i
        'ѕ': 's',  # Cyrillic ѕ → Latin s
        'һ': 'h',  # Cyrillic һ → Latin h
        'ԁ': 'd',  # Cyrillic ԁ → Latin d
        'ј': 'j',  # Cyrillic ј → Latin j
        'м': 'm',  # Cyrillic м → Latin m
        'т': 't',  # Cyrillic т → Latin t
    }

    @staticmethod
    def detect_homoglyphs(domain: str) -> Dict[str, any]:
        """
        Detect if a domain contains homoglyphs (lookalike characters).

        Args:
            domain: Domain name to check

        Returns:
            Dictionary with detection results
        """
        homoglyphs_found = []
        latin_equivalent = []

        for i, char in enumerate(domain):
            # Check if it's a Cyrillic character
            if char in TyposquattingDetector.CYRILLIC_LOOKALIKES:
                latin_char = TyposquattingDetector.CYRILLIC_LOOKALIKES[char]
                homoglyphs_found.append({
                    'position': i,
                    'character': char,
                    'unicode_name': unicodedata.name(char, 'UNKNOWN'),
                    'unicode_code': f'U+{ord(char):04X}',
                    'looks_like': latin_char
                })
                latin_equivalent.append(latin_char)
            else:
                latin_equivalent.append(char)

        return {
            'has_homoglyphs': len(homoglyphs_found) > 0,
            'homoglyphs': homoglyphs_found,
            'latin_equivalent': ''.join(latin_equivalent)
        }

    @staticmethod
    def generate_substitution_variants(domain: str, max_substitutions: int = 2) -> List[str]:
        """
        Generate domain variants using character substitution.

        For example, "google" could become:
        - "g0ogle" (o → 0)
        - "googIe" (l → I)
        - "gооgle" (o → Cyrillic о)

        Args:
            domain: Original domain name
            max_substitutions: Maximum number of characters to substitute

        Returns:
            List of domain variants
        """
        variants = set()
        domain_lower = domain.lower()

        # Find positions where substitutions are possible
        substitutable_positions = []
        for i, char in enumerate(domain_lower):
            if char in TyposquattingDetector.SUBSTITUTIONS:
                substitutable_positions.append(i)

        # Generate variants with 1 to max_substitutions
        for num_subs in range(1, min(max_substitutions + 1, len(substitutable_positions) + 1)):
            # Choose which positions to substitute
            for positions in combinations(substitutable_positions, num_subs):
                # For each combination of positions
                chars = list(domain_lower)

                # Get all possible substitutions for these positions
                def generate_recursive(pos_index, current_chars):
                    if pos_index >= len(positions):
                        variants.add(''.join(current_chars))
                        return

                    pos = positions[pos_index]
                    original_char = domain_lower[pos]

                    # Try each substitution for this character
                    for sub_char in TyposquattingDetector.SUBSTITUTIONS[original_char]:
                        current_chars[pos] = sub_char
                        generate_recursive(pos_index + 1, current_chars[:])

                generate_recursive(0, chars[:])

        # Remove the original domain
        variants.discard(domain_lower)

        return list(variants)[:100]  # Limit to 100 variants to avoid overwhelming

    @staticmethod
    def generate_cyrillic_variants(domain: str) -> List[str]:
        """
        Generate Cyrillic lookalike variants of a domain.

        Replaces Latin characters with visually similar Cyrillic ones.
        For example: "google" → "gооgle" (with Cyrillic о)

        Args:
            domain: Original domain name (Latin characters)

        Returns:
            List of Cyrillic variants
        """
        variants = set()
        domain_lower = domain.lower()

        # Reverse mapping: Latin → Cyrillic
        latin_to_cyrillic = {v: k for k, v in TyposquattingDetector.CYRILLIC_LOOKALIKES.items()}

        # Find positions where Cyrillic substitution is possible
        substitutable_positions = []
        for i, char in enumerate(domain_lower):
            if char in latin_to_cyrillic:
                substitutable_positions.append(i)

        # Generate all combinations (up to 3 substitutions for performance)
        max_subs = min(3, len(substitutable_positions))

        for num_subs in range(1, max_subs + 1):
            for positions in combinations(substitutable_positions, num_subs):
                chars = list(domain_lower)
                for pos in positions:
                    chars[pos] = latin_to_cyrillic[domain_lower[pos]]
                variants.add(''.join(chars))

        return list(variants)

    @staticmethod
    def generate_typo_variants(domain: str) -> List[str]:
        """
        Generate common typo variants.

        - Missing characters: "google" → "gogle"
        - Swapped characters: "google" → "goolge"
        - Duplicate characters: "google" → "gooogle"
        - Adjacent key typos: "google" → "foogle" (g→f on keyboard)

        Args:
            domain: Original domain name

        Returns:
            List of typo variants
        """
        variants = set()
        domain_lower = domain.lower()

        # 1. Missing characters (omission)
        for i in range(len(domain_lower)):
            variant = domain_lower[:i] + domain_lower[i+1:]
            if variant:  # Don't add empty string
                variants.add(variant)

        # 2. Swapped adjacent characters (transposition)
        for i in range(len(domain_lower) - 1):
            chars = list(domain_lower)
            chars[i], chars[i+1] = chars[i+1], chars[i]
            variants.add(''.join(chars))

        # 3. Duplicate characters (repetition)
        for i in range(len(domain_lower)):
            variant = domain_lower[:i+1] + domain_lower[i] + domain_lower[i+1:]
            variants.add(variant)

        # 4. Adjacent key typos (keyboard proximity - simplified)
        keyboard_adjacent = {
            'q': ['w', 'a'], 'w': ['q', 'e', 's'], 'e': ['w', 'r', 'd'],
            'r': ['e', 't', 'f'], 't': ['r', 'y', 'g'], 'y': ['t', 'u', 'h'],
            'u': ['y', 'i', 'j'], 'i': ['u', 'o', 'k'], 'o': ['i', 'p', 'l'],
            'p': ['o', 'l'], 'a': ['q', 's', 'z'], 's': ['w', 'a', 'd', 'x'],
            'd': ['e', 's', 'f', 'c'], 'f': ['r', 'd', 'g', 'v'],
            'g': ['t', 'f', 'h', 'b'], 'h': ['y', 'g', 'j', 'n'],
            'j': ['u', 'h', 'k', 'm'], 'k': ['i', 'j', 'l'], 'l': ['o', 'k'],
            'z': ['a', 'x'], 'x': ['z', 's', 'c'], 'c': ['x', 'd', 'v'],
            'v': ['c', 'f', 'b'], 'b': ['v', 'g', 'n'], 'n': ['b', 'h', 'm'],
            'm': ['n', 'j']
        }

        for i, char in enumerate(domain_lower):
            if char in keyboard_adjacent:
                for adjacent in keyboard_adjacent[char]:
                    variant = domain_lower[:i] + adjacent + domain_lower[i+1:]
                    variants.add(variant)

        # Remove original
        variants.discard(domain_lower)

        return list(variants)[:50]  # Limit to 50 variants

    @staticmethod
    def compare_domains(original: str, suspicious: str) -> Dict[str, any]:
        """
        Compare two domains to detect typosquatting.

        Args:
            original: The legitimate domain
            suspicious: The potentially malicious domain

        Returns:
            Dictionary with comparison results and typosquatting indicators
        """
        # Remove TLD for comparison
        original_base = original.split('.')[0].lower()
        suspicious_base = suspicious.split('.')[0].lower()

        # Calculate Levenshtein distance (edit distance)
        distance = TyposquattingDetector._levenshtein_distance(original_base, suspicious_base)

        # Check for homoglyphs
        homoglyph_info = TyposquattingDetector.detect_homoglyphs(suspicious_base)

        # Check if suspicious is in generated variants
        all_variants = set()
        all_variants.update(TyposquattingDetector.generate_substitution_variants(original_base, 2))
        all_variants.update(TyposquattingDetector.generate_cyrillic_variants(original_base))
        all_variants.update(TyposquattingDetector.generate_typo_variants(original_base))

        is_variant = suspicious_base in all_variants

        # Determine risk level
        risk_level = "NONE"
        risk_score = 0
        indicators = []

        if distance == 0 and homoglyph_info['has_homoglyphs']:
            risk_level = "CRITICAL"
            risk_score = 100
            indicators.append("Identical domain with homoglyphs (e.g., Cyrillic characters)")
        elif is_variant:
            risk_level = "HIGH"
            risk_score = 80
            indicators.append("Known typosquatting variant")
        elif distance == 1:
            risk_level = "HIGH"
            risk_score = 75
            indicators.append("One character difference")
        elif distance == 2:
            risk_level = "MEDIUM"
            risk_score = 50
            indicators.append("Two character difference")
        elif distance <= 3:
            risk_level = "LOW"
            risk_score = 30
            indicators.append("Similar domain (3 characters different)")

        if homoglyph_info['has_homoglyphs'] and risk_level != "CRITICAL":
            risk_score += 30
            if risk_score >= 80:
                risk_level = "HIGH"
            elif risk_score >= 50:
                risk_level = "MEDIUM"
            indicators.append(f"Contains {len(homoglyph_info['homoglyphs'])} homoglyph(s)")

        return {
            'original': original,
            'suspicious': suspicious,
            'edit_distance': distance,
            'is_known_variant': is_variant,
            'homoglyphs': homoglyph_info,
            'risk_level': risk_level,
            'risk_score': risk_score,
            'indicators': indicators
        }

    @staticmethod
    def _levenshtein_distance(s1: str, s2: str) -> int:
        """
        Calculate Levenshtein distance (edit distance) between two strings.

        The minimum number of single-character edits (insertions, deletions,
        or substitutions) required to change one string into the other.
        """
        if len(s1) < len(s2):
            return TyposquattingDetector._levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                # Cost of insertions, deletions, or substitutions
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    @staticmethod
    def scan_for_typosquatting(original_domain: str, check_registration: bool = True) -> List[Dict]:
        """
        Scan for potential typosquatting domains.

        Generates variants and optionally checks if they are registered.

        Args:
            original_domain: The legitimate domain to protect
            check_registration: If True, verify which variants are actually registered

        Returns:
            List of dictionaries with variant information
        """
        print(f"\n[*] Scanning for typosquatting variants of: {original_domain}")
        print("="*70)

        domain_base = original_domain.split('.')[0]
        tld = '.'.join(original_domain.split('.')[1:]) if '.' in original_domain else 'com'

        # Generate all variants
        print("\n[*] Generating variants...")
        substitution_variants = TyposquattingDetector.generate_substitution_variants(domain_base, 2)
        cyrillic_variants = TyposquattingDetector.generate_cyrillic_variants(domain_base)
        typo_variants = TyposquattingDetector.generate_typo_variants(domain_base)

        all_variants = set(substitution_variants + cyrillic_variants + typo_variants)

        print(f"[+] Generated {len(all_variants)} unique variants")
        print(f"    - Substitution variants: {len(substitution_variants)}")
        print(f"    - Cyrillic variants: {len(cyrillic_variants)}")
        print(f"    - Typo variants: {len(typo_variants)}")

        results = []

        if check_registration:
            print(f"\n[*] Checking registration status (this may take a while)...")
            registered_count = 0

            for i, variant in enumerate(list(all_variants)[:20], 1):  # Limit to 20 to avoid rate limits
                variant_domain = f"{variant}.{tld}"
                print(f"\r[{i}/20] Checking: {variant_domain}...", end='', flush=True)

                info = DomainVerifier.verify_domain(variant_domain)

                if info:
                    registered_count += 1
                    comparison = TyposquattingDetector.compare_domains(original_domain, variant_domain)
                    results.append({
                        'variant': variant_domain,
                        'registered': True,
                        'registration_date': info.registration_date,
                        'age_days': info.age_days,
                        'registrar': info.registrar,
                        'comparison': comparison
                    })

            print(f"\n\n[+] Found {registered_count} registered variants")
        else:
            # Just return the variants without checking registration
            for variant in all_variants:
                variant_domain = f"{variant}.{tld}"
                comparison = TyposquattingDetector.compare_domains(original_domain, variant_domain)
                results.append({
                    'variant': variant_domain,
                    'registered': None,
                    'comparison': comparison
                })

        return results


def print_comparison_result(result: Dict):
    """Pretty print a domain comparison result."""
    print("\n" + "="*70)
    print(f"🔍 Comparing: {result['original']} vs {result['suspicious']}")
    print("="*70)

    # Risk level with color emoji
    risk_emoji = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢",
        "NONE": "⚪"
    }

    print(f"\n{risk_emoji.get(result['risk_level'], '❓')} Risk Level: {result['risk_level']} (Score: {result['risk_score']}/100)")

    if result['indicators']:
        print("\n⚠️  Risk Indicators:")
        for indicator in result['indicators']:
            print(f"   • {indicator}")

    print(f"\n📊 Edit Distance: {result['edit_distance']}")
    print(f"📝 Known Variant: {'Yes' if result['is_known_variant'] else 'No'}")

    # Homoglyph details
    if result['homoglyphs']['has_homoglyphs']:
        print(f"\n🎭 Homoglyphs Detected:")
        for hg in result['homoglyphs']['homoglyphs']:
            print(f"   Position {hg['position']}: '{hg['character']}' ({hg['unicode_name']})")
            print(f"   → Unicode: {hg['unicode_code']}")
            print(f"   → Looks like: '{hg['looks_like']}'")
        print(f"\n   Latin equivalent: {result['homoglyphs']['latin_equivalent']}")
    else:
        print("\n✅ No homoglyphs detected")

    print("="*70)


if __name__ == "__main__":
    # Example usage
    print("="*70)
    print(" Typosquatting Detection Examples")
    print("="*70)

    # Example 1: Compare google vs googIe (I instead of l)
    print("\n\n" + "="*70)
    print("Example 1: Character Substitution (l → I)")
    print("="*70)
    result = TyposquattingDetector.compare_domains("google.com", "googIe.com")
    print_comparison_result(result)

    # Example 2: Cyrillic lookalikes
    print("\n\n" + "="*70)
    print("Example 2: Cyrillic Lookalikes")
    print("="*70)

    # Create a domain with Cyrillic 'о' instead of Latin 'o'
    cyrillic_google = "gооgle.com"  # Contains Cyrillic 'о'
    result = TyposquattingDetector.compare_domains("google.com", cyrillic_google)
    print_comparison_result(result)

    # Example 3: Generate variants
    print("\n\n" + "="*70)
    print("Example 3: Generate Typosquatting Variants")
    print("="*70)

    print("\n[*] Substitution variants of 'google':")
    subs = TyposquattingDetector.generate_substitution_variants("google", 1)[:10]
    for variant in subs:
        print(f"   • {variant}")

    print("\n[*] Cyrillic variants of 'google':")
    cyrs = TyposquattingDetector.generate_cyrillic_variants("google")[:10]
    for variant in cyrs:
        print(f"   • {variant}")
        # Show which characters are Cyrillic
        hg = TyposquattingDetector.detect_homoglyphs(variant)
        if hg['has_homoglyphs']:
            positions = [str(h['position']) for h in hg['homoglyphs']]
            print(f"     (Cyrillic at position(s): {', '.join(positions)})")

    print("\n[*] Common typo variants of 'google':")
    typos = TyposquattingDetector.generate_typo_variants("google")[:10]
    for variant in typos:
        print(f"   • {variant}")
