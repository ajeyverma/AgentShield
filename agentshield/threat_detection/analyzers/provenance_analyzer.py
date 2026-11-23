"""
AgentShield AI — Provenance Analyzer.

Assesses the trustworthiness of instructions and data inputs based on their
lineage and origin integration point.
"""

from __future__ import annotations

from agentshield.contracts.provenance import ProvenanceContext, SourceType, TrustLevel


class ProvenanceAnalyzer:
    """Evaluates whether an action was driven by untrusted or external content."""

    UNTRUSTED_SOURCES = {
        SourceType.WEBPAGE,
        SourceType.EMAIL,
        SourceType.DOCUMENT,
        SourceType.IMAGE_OCR,
        SourceType.EXTERNAL_API,
        SourceType.UNKNOWN,
    }

    @classmethod
    def assess_trust(cls, context: ProvenanceContext | None) -> tuple[TrustLevel, list[str]]:
        """Determine effective trust level and return itemized findings."""
        if context is None:
            return TrustLevel.UNKNOWN, ["Missing provenance context: source trustworthiness cannot be verified."]

        reasons = []
        is_untrusted = False

        if context.primary_source:
            if context.primary_source.trust_level == TrustLevel.UNTRUSTED:
                is_untrusted = True
                reasons.append(
                    f"Primary instruction origin '{context.primary_source.source_type.value}' is explicitly UNTRUSTED."
                )
            elif context.primary_source.source_type in cls.UNTRUSTED_SOURCES:
                is_untrusted = True
                reasons.append(
                    f"Primary instruction origin '{context.primary_source.source_type.value}' is classified as external/untrusted."
                )

        for rec in context.records:
            if rec.trust_level == TrustLevel.UNTRUSTED:
                is_untrusted = True
                reasons.append(f"Associated record '{rec.source_type.value}' from '{rec.origin or 'unknown'}' is UNTRUSTED.")
            elif rec.source_type in cls.UNTRUSTED_SOURCES and rec.trust_level != TrustLevel.TRUSTED:
                is_untrusted = True
                reasons.append(f"Associated record '{rec.source_type.value}' is external and unverified.")

        if is_untrusted:
            return TrustLevel.UNTRUSTED, reasons

        if not context.records and not context.primary_source:
            return TrustLevel.UNKNOWN, ["Empty provenance lineage."]

        return TrustLevel.TRUSTED, ["Instruction lineage verified from trusted origin."]
