"""
AgentShield AI — Provenance Contracts (Phase 5).

Provides structured data models for tracking information source provenance,
trust classifications, and transformation integrity across AI agent inputs.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class SourceType(str, Enum):
    """Origin category of input data or instructions."""

    USER_INPUT = "user_input"
    SYSTEM_INSTRUCTION = "system_instruction"
    DEVELOPER_INSTRUCTION = "developer_instruction"
    WEBPAGE = "webpage"
    EMAIL = "email"
    DOCUMENT = "document"
    IMAGE_OCR = "image_ocr"
    TOOL_OUTPUT = "tool_output"
    EXTERNAL_API = "external_api"
    DATABASE = "database"
    UNKNOWN = "unknown"


class TrustLevel(str, Enum):
    """Trust classification assigned by trusted ingestion boundaries."""

    TRUSTED = "TRUSTED"
    UNTRUSTED = "UNTRUSTED"
    UNKNOWN = "UNKNOWN"


class ProvenanceRecord(BaseModel):
    """An individual record describing the lineage of a piece of data."""

    source_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_type: SourceType = Field(default=SourceType.UNKNOWN)
    trust_level: TrustLevel = Field(default=TrustLevel.UNKNOWN)
    origin: str | None = Field(default=None, description="URL, filepath, message ID, or channel")
    content_reference: str | None = Field(default=None, description="Hash or excerpt reference")
    received_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    parent_source_id: str | None = Field(default=None)
    transformation_type: str | None = Field(default=None)
    integrity_metadata: dict[str, Any] = Field(default_factory=dict)


class ProvenanceContext(BaseModel):
    """Aggregated provenance context associated with an ActionRequest."""

    context_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    primary_source: ProvenanceRecord | None = None
    records: list[ProvenanceRecord] = Field(default_factory=list)
    raw_content_preview: str | None = Field(default=None, max_length=1000)

    @property
    def is_untrusted(self) -> bool:
        """Return True if any associated provenance source is UNTRUSTED or UNKNOWN."""
        if not self.records and not self.primary_source:
            return True
        if self.primary_source and self.primary_source.trust_level != TrustLevel.TRUSTED:
            return True
        return any(r.trust_level != TrustLevel.TRUSTED for r in self.records)

    @classmethod
    def from_user(cls, user_id: str, prompt_text: str | None = None) -> ProvenanceContext:
        """Convenience factory for direct trusted user input."""
        rec = ProvenanceRecord(
            source_type=SourceType.USER_INPUT,
            trust_level=TrustLevel.TRUSTED,
            origin=f"user:{user_id}",
        )
        return cls(primary_source=rec, records=[rec], raw_content_preview=(prompt_text[:200] if prompt_text else None))

    @classmethod
    def from_untrusted(cls, source_type: SourceType, origin: str | None = None, content_snippet: str | None = None) -> ProvenanceContext:
        """Convenience factory for untrusted external ingestion."""
        rec = ProvenanceRecord(
            source_type=source_type,
            trust_level=TrustLevel.UNTRUSTED,
            origin=origin,
        )
        return cls(primary_source=rec, records=[rec], raw_content_preview=(content_snippet[:200] if content_snippet else None))
