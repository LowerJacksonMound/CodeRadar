"""
Signature signature database for runtime signatures detection.

Provides a database interface for managing and querying signatures signatures.
"""

import asyncio
import logging
import os
import re
from collections.abc import Iterator
from dataclasses import dataclass, field

from signature_engine.core import AuthorshipSignature
from signature_engine.authorship_rules import DEFAULT_AUTHORSHIP_SIGNATURES

logger = logging.getLogger(__name__)
DEBUG = os.environ.get("SIGNATURE_ENGINE_DEBUG", "").lower() in ("1", "true", "yes")


def _trace(msg: str, *args: object) -> None:
    if DEBUG:
        logger.debug(msg, *args)


@dataclass
class MatchResult:
    """Result of a signature match."""
    signature: AuthorshipSignature
    line_number: int
    line_content: str
    match_start: int
    match_end: int

    @property
    def matched_text(self) -> str:
        """Get the matched text."""
        return self.line_content[self.match_start:self.match_end]


@dataclass
class ScanResult:
    """Result of scanning code with all signatures."""
    matches: list[MatchResult] = field(default_factory=list)
    lines_scanned: int = 0
    signatures_checked: int = 0

    def __len__(self) -> int:
        return len(self.matches)

    def __iter__(self) -> Iterator[MatchResult]:
        return iter(self.matches)

    def by_severity(self, severity: str) -> list[MatchResult]:
        """Get matches by severity."""
        return [m for m in self.matches if m.signature.severity == severity]

    def by_category(self, category: str) -> list[MatchResult]:
        """Get matches by category."""
        return [m for m in self.matches if m.signature.category == category]

    def has_critical(self) -> bool:
        """Check if there are any critical matches."""
        return any(m.signature.severity == "critical" for m in self.matches)

    def has_high(self) -> bool:
        """Check if there are any high severity matches."""
        return any(m.signature.severity == "high" for m in self.matches)

    def summary(self) -> dict[str, object]:
        """Get a summary of the scan results."""
        severity_counts: dict[str, int] = {}
        category_counts: dict[str, int] = {}

        for match in self.matches:
            sev = match.signature.severity
            cat = match.signature.category
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            category_counts[cat] = category_counts.get(cat, 0) + 1

        return {
            "total_matches": len(self.matches),
            "lines_scanned": self.lines_scanned,
            "signatures_checked": self.signatures_checked,
            "by_severity": severity_counts,
            "by_category": category_counts,
            "has_critical": self.has_critical(),
            "has_high": self.has_high(),
        }


class AuthorshipSignatureDatabase:
    """Database for signatures signatures with query and match capabilities."""

    def __init__(self, signatures: list[AuthorshipSignature] | None = None):
        """Initialize the database with signatures.

        Args:
            signatures: List of signatures. If None, uses DEFAULT_AUTHORSHIP_SIGNATURES.
        """
        _trace("AuthorshipSignatureDatabase.__init__ custom=%s", signatures is not None)
        self._signatures: list[AuthorshipSignature] = list(
            DEFAULT_AUTHORSHIP_SIGNATURES if signatures is None else signatures
        )
        self._compiled_patterns: dict[str, re.Pattern[str]] = {}
        self._name_index: dict[str, AuthorshipSignature] = {}
        self._category_index: dict[str, list[AuthorshipSignature]] = {}
        self._severity_index: dict[str, list[AuthorshipSignature]] = {}
        self._tag_index: dict[str, list[AuthorshipSignature]] = {}

        self._build_indices()
        _trace("AuthorshipSignatureDatabase ready: %d signatures indexed", len(self._signatures))

    def _build_indices(self) -> None:
        """Build lookup indices for efficient querying."""
        self._name_index.clear()
        self._category_index.clear()
        self._severity_index.clear()
        self._tag_index.clear()
        self._compiled_patterns.clear()

        for sig in self._signatures:
            self._add_to_indices(sig)

    def _add_to_indices(self, sig: AuthorshipSignature) -> None:
        """Add a single signature to all indices."""
        # Name index
        self._name_index[sig.name] = sig

        # Category index
        if sig.category not in self._category_index:
            self._category_index[sig.category] = []
        self._category_index[sig.category].append(sig)

        # Severity index
        if sig.severity not in self._severity_index:
            self._severity_index[sig.severity] = []
        self._severity_index[sig.severity].append(sig)

        # Tag index
        for tag in sig.tags:
            if tag not in self._tag_index:
                self._tag_index[tag] = []
            self._tag_index[tag].append(sig)

        # Compile pattern
        if sig.pattern:
            try:
                flags = re.MULTILINE
                if sig.multiline:
                    flags |= re.DOTALL
                self._compiled_patterns[sig.name] = re.compile(sig.pattern, flags)
            except re.error as e:
                logger.warning(
                    "Invalid regex pattern in signature '%s': %s", sig.name, e
                )

    def _remove_from_indices(self, sig: AuthorshipSignature) -> None:
        """Remove a single signature from all indices."""
        # Name index
        self._name_index.pop(sig.name, None)

        # Category index
        if sig.category in self._category_index:
            cat_list = self._category_index[sig.category]
            if sig in cat_list:
                cat_list.remove(sig)
            if not cat_list:
                del self._category_index[sig.category]

        # Severity index
        if sig.severity in self._severity_index:
            sev_list = self._severity_index[sig.severity]
            if sig in sev_list:
                sev_list.remove(sig)
            if not sev_list:
                del self._severity_index[sig.severity]

        # Tag index
        for tag in sig.tags:
            if tag in self._tag_index:
                tag_list = self._tag_index[tag]
                if sig in tag_list:
                    tag_list.remove(sig)
                if not tag_list:
                    del self._tag_index[tag]

        # Remove compiled pattern
        self._compiled_patterns.pop(sig.name, None)

    def __len__(self) -> int:
        """Return the number of signatures."""
        return len(self._signatures)

    def __iter__(self) -> Iterator[AuthorshipSignature]:
        """Iterate over all signatures."""
        return iter(self._signatures)

    def __contains__(self, name: str) -> bool:
        """Check if a signature exists by name."""
        return name in self._name_index

    def get(self, name: str) -> AuthorshipSignature | None:
        """Get a signature by name."""
        return self._name_index.get(name)

    def add(self, signature: AuthorshipSignature) -> None:
        """Add a signature to the database."""
        self._signatures.append(signature)
        self._add_to_indices(signature)

    def remove(self, name: str) -> bool:
        """Remove a signature by name.

        Returns True if removed, False if not found.
        """
        sig = self._name_index.get(name)
        if sig:
            self._signatures.remove(sig)
            self._remove_from_indices(sig)
            return True
        return False

    def by_category(self, category: str) -> list[AuthorshipSignature]:
        """Get all signatures in a category."""
        return list(self._category_index.get(category, []))

    def by_severity(self, severity: str) -> list[AuthorshipSignature]:
        """Get all signatures with a severity."""
        return list(self._severity_index.get(severity, []))

    def by_tag(self, tag: str) -> list[AuthorshipSignature]:
        """Get all signatures with a tag."""
        return list(self._tag_index.get(tag, []))

    def categories(self) -> list[str]:
        """Get all categories."""
        return list(self._category_index.keys())

    def severities(self) -> list[str]:
        """Get all severities."""
        return list(self._severity_index.keys())

    def tags(self) -> list[str]:
        """Get all tags."""
        return list(self._tag_index.keys())

    def match_line(self, line: str, line_number: int = 0) -> list[MatchResult]:
        """Match a single line against all signatures.

        Args:
            line: The line of code to check.
            line_number: The line number for the result.

        Returns:
            List of MatchResult for all matching signatures.
        """
        _trace("match_line L%d: %r", line_number, line[:80])
        results = []

        for sig in self._signatures:
            if sig.pattern is None:
                continue

            pattern = self._compiled_patterns.get(sig.name)
            if pattern is None:
                continue

            for match in pattern.finditer(line):
                results.append(
                    MatchResult(
                        signature=sig,
                        line_number=line_number,
                        line_content=line,
                        match_start=match.start(),
                        match_end=match.end(),
                    )
                )

        return results

    def _filter_signatures(
        self,
        categories: list[str] | None = None,
        severities: list[str] | None = None,
        tags: list[str] | None = None,
    ) -> list[AuthorshipSignature]:
        """Filter signatures by categories, severities, and tags."""
        signatures = self._signatures
        if categories:
            signatures = [s for s in signatures if s.category in categories]
        if severities:
            signatures = [s for s in signatures if s.severity in severities]
        if tags:
            signatures = [s for s in signatures if any(t in s.tags for t in tags)]
        return signatures

    def _scan_singleline(
        self,
        lines: list[str],
        signatures: list[AuthorshipSignature],
    ) -> list[MatchResult]:
        """Scan lines for single-line pattern matches."""
        matches: list[MatchResult] = []
        for line_num, line in enumerate(lines, 1):
            for sig in signatures:
                pattern = self._compiled_patterns.get(sig.name) if sig.pattern else None
                if pattern is None:
                    continue
                for match in pattern.finditer(line):
                    matches.append(
                        MatchResult(
                            signature=sig,
                            line_number=line_num,
                            line_content=line,
                            match_start=match.start(),
                            match_end=match.end(),
                        )
                    )
        return matches

    def _scan_multiline_patterns(
        self,
        code: str,
        signatures: list[AuthorshipSignature],
    ) -> list[MatchResult]:
        """Scan code for multiline pattern matches."""
        matches: list[MatchResult] = []
        for sig in signatures:
            pattern = self._compiled_patterns.get(sig.name) if sig.pattern else None
            if pattern is None:
                continue
            for match in pattern.finditer(code):
                line_num = code[:match.start()].count("\n") + 1
                line_start = code.rfind("\n", 0, match.start()) + 1
                line_end = code.find("\n", match.end())
                line_end = len(code) if line_end == -1 else line_end
                line_content = code[line_start:line_end]
                matches.append(
                    MatchResult(
                        signature=sig,
                        line_number=line_num,
                        line_content=line_content,
                        match_start=match.start() - line_start,
                        match_end=min(match.end() - line_start, len(line_content)),
                    )
                )
        return matches

    def scan(
        self,
        code: str,
        categories: list[str] | None = None,
        severities: list[str] | None = None,
        tags: list[str] | None = None,
    ) -> ScanResult:
        """Scan code for signatures patterns.

        Args:
            code: The code to scan.
            categories: Only check these categories. None = all.
            severities: Only check these severities. None = all.
            tags: Only check signatures with these tags. None = all.

        Returns:
            ScanResult with all matches.
        """
        _trace("scan: %d chars, categories=%s, severities=%s, tags=%s",
               len(code), categories, severities, tags)
        signatures = self._filter_signatures(categories, severities, tags)
        lines = code.splitlines()

        result = ScanResult(
            signatures_checked=len(signatures),
            lines_scanned=len(lines),
        )

        # Separate and scan single-line vs multiline signatures
        singleline_sigs = [s for s in signatures if not s.multiline]
        multiline_sigs = [s for s in signatures if s.multiline]

        result.matches.extend(self._scan_singleline(lines, singleline_sigs))
        result.matches.extend(self._scan_multiline_patterns(code, multiline_sigs))

        _trace("scan complete: %d matches across %d lines", len(result), result.lines_scanned)
        return result

    def scan_multiline(
        self,
        code: str,
        categories: list[str] | None = None,
        severities: list[str] | None = None,
    ) -> ScanResult:
        """Scan code with multiline pattern support.

        Some patterns need to match across multiple lines.
        This is slower but more thorough.
        """
        signatures = self._signatures
        if categories:
            signatures = [s for s in signatures if s.category in categories]
        if severities:
            signatures = [s for s in signatures if s.severity in severities]

        result = ScanResult(signatures_checked=len(signatures))
        result.lines_scanned = code.count("\n") + 1

        for sig in signatures:
            if sig.pattern is None:
                continue

            pattern = self._compiled_patterns.get(sig.name)
            if pattern is None:
                continue

            for match in pattern.finditer(code):
                # Calculate line number from position
                line_num = code[:match.start()].count("\n") + 1
                # Get the line content
                line_start = code.rfind("\n", 0, match.start()) + 1
                line_end = code.find("\n", match.end())
                if line_end == -1:
                    line_end = len(code)
                line_content = code[line_start:line_end]

                result.matches.append(
                    MatchResult(
                        signature=sig,
                        line_number=line_num,
                        line_content=line_content,
                        match_start=match.start() - line_start,
                        match_end=min(match.end() - line_start, len(line_content)),
                    )
                )

        return result

    def statistics(self) -> dict[str, object]:
        """Get statistics about the database."""
        pattern_count = sum(1 for s in self._signatures if s.pattern)
        metric_count = sum(1 for s in self._signatures if s.metric)

        return {
            "total_signatures": len(self._signatures),
            "pattern_signatures": pattern_count,
            "metric_signatures": metric_count,
            "categories": len(self._category_index),
            "severities": len(self._severity_index),
            "tags": len(self._tag_index),
            "category_breakdown": {
                cat: len(sigs) for cat, sigs in self._category_index.items()
            },
            "severity_breakdown": {
                sev: len(sigs) for sev, sigs in self._severity_index.items()
            },
        }


# Async-safe singleton database instance
_signature_database: AuthorshipSignatureDatabase | None = None
_signature_database_lock = asyncio.Lock()


async def get_signature_database() -> AuthorshipSignatureDatabase:
    """Get the singleton signatures database instance (async-safe)."""
    global _signature_database
    if _signature_database is None:
        async with _signature_database_lock:
            if _signature_database is None:
                _signature_database = AuthorshipSignatureDatabase()
    return _signature_database


async def reset_signature_database() -> None:
    """Reset the singleton signatures database (async-safe)."""
    global _signature_database
    async with _signature_database_lock:
        _signature_database = None


def get_default_signatures() -> list[AuthorshipSignature]:
    """Get a fresh copy of the default signatures signatures.

    Returns a new list each time to prevent accidental mutation of the defaults.
    """
    return list(DEFAULT_AUTHORSHIP_SIGNATURES)


# Convenience export - NOTE: This is a snapshot copy, use get_default_signatures()
# for a fresh copy if you need to modify it.
AUTHORSHIP_SIGNATURES: list[AuthorshipSignature] = list(DEFAULT_AUTHORSHIP_SIGNATURES)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python signatures.py <file.py>")
        sys.exit(1)

    source = open(sys.argv[1], encoding="utf-8").read()
    db = AuthorshipSignatureDatabase()
    result = db.scan(source)
    print(f"File: {sys.argv[1]}")
    print(f"  Signatures loaded: {len(db._signatures)}")
    print(f"  Matches: {len(result.matches)}")
    for m in result.matches[:10]:
        print(f"    [{m.signature.severity}] {m.signature.name} (line {m.line_number})")
    print(f"  Default signatures: {len(get_default_signatures())}")
