"""
KEKAI Autonomous Brand Intelligence & Phishing Engine
Pre-Interaction Message Ingestion Layer
==================================================================================
Provides a normalized, vendor-agnostic message ingestion schema and adapter interface.
Ingests messages BEFORE a user interacts with them. Performs static IOC extraction
without executing attachments, HTML scripts, macros, or external URLs.
"""

import uuid
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

logger = logging.getLogger("kekai.message_ingestion")


class AttachmentMetadata(BaseModel):
    filename: str = Field(..., description="Attachment filename e.g. invoice.pdf")
    mime_type: Optional[str] = Field("application/octet-stream", description="Declared MIME type")
    file_size_bytes: Optional[int] = Field(0, description="Attachment size in bytes")
    sha256: Optional[str] = Field(None, description="SHA256 hash of attachment")
    is_executable: bool = Field(False, description="Whether file has executable signature")
    has_html_form: bool = Field(False, description="Whether attachment contains HTML login form")


class NormalizedMessage(BaseModel):
    message_id: str = Field(default_factory=lambda: f"MSG-{uuid.uuid4().hex[:10].upper()}")
    sender: str = Field(..., example="finance@acme.example", description="Sender email address")
    recipients: List[str] = Field(default_factory=list, description="Recipient email addresses")
    subject: str = Field("", description="Message subject line")
    body: str = Field("", description="Message text or HTML content")
    headers: Dict[str, Any] = Field(default_factory=dict, description="Raw message headers")
    attachments_metadata: List[AttachmentMetadata] = Field(default_factory=list, description="Static attachment metadata")
    urls: List[str] = Field(default_factory=list, description="Extracted URLs")
    source: str = Field("email_gateway_proxy", description="Ingestion source adapter name")
    received_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    organisation_id: str = Field("org_acme_01", description="Target organisation identifier")


class MessageSourceAdapter(ABC):
    """
    Abstract Base Class for Message Source Adapters.
    Future adapters (e.g. SMTP Proxy, Security Gateway, Webhook) inherit from this interface.
    """

    @abstractmethod
    def ingest(self, raw_data: Dict[str, Any]) -> NormalizedMessage:
        pass


class StandardMessageAdapter(MessageSourceAdapter):
    """
    Default pre-interaction message adapter. Safely normalizes raw payload.
    """

    def ingest(self, raw_data: Dict[str, Any]) -> NormalizedMessage:
        msg_id = raw_data.get("message_id") or f"MSG-{uuid.uuid4().hex[:10].upper()}"
        sender = (raw_data.get("sender") or raw_data.get("from") or "unknown@sender.example").strip()
        recipients = raw_data.get("recipients") or ([raw_data["to"]] if "to" in raw_data else ["user@acme.example"])
        subject = raw_data.get("subject", "").strip()
        body = raw_data.get("body") or raw_data.get("text", "") or raw_data.get("content", "")
        headers = raw_data.get("headers") or {}
        source = raw_data.get("source", "standard_pre_interaction_gateway")
        org_id = raw_data.get("organisation_id", "org_acme_01")
        received_at = raw_data.get("received_at") or datetime.now(timezone.utc).isoformat()

        # Parse attachment metadata without executing code
        raw_atts = raw_data.get("attachments_metadata") or raw_data.get("attachments") or []
        attachments = []
        for att in raw_atts:
            if isinstance(att, dict):
                fname = att.get("filename") or att.get("name") or "attachment.bin"
                attachments.append(AttachmentMetadata(
                    filename=fname,
                    mime_type=att.get("mime_type") or att.get("content_type") or "application/octet-stream",
                    file_size_bytes=int(att.get("file_size_bytes") or att.get("size") or 0),
                    sha256=att.get("sha256"),
                    is_executable=bool(att.get("is_executable") or fname.endswith((".exe", ".bat", ".scr", ".vbs"))),
                    has_html_form=bool(att.get("has_html_form") or att.get("is_html_form"))
                ))

        # Extract URLs safely using static parser
        from services.email_analysis import extract_iocs
        iocs = extract_iocs(subject=subject, sender=sender, body=body)
        urls = sorted(list(set(iocs.get("urls", []) + raw_data.get("urls", []))))

        return NormalizedMessage(
            message_id=msg_id,
            sender=sender,
            recipients=recipients if isinstance(recipients, list) else [str(recipients)],
            subject=subject,
            body=body,
            headers=headers if isinstance(headers, dict) else {},
            attachments_metadata=attachments,
            urls=urls,
            source=source,
            received_at=received_at,
            organisation_id=org_id
        )


def ingest_pre_interaction_message(raw_data: Dict[str, Any]) -> NormalizedMessage:
    """
    Utility helper to ingest and normalize any incoming message payload safely.
    """
    adapter = StandardMessageAdapter()
    return adapter.ingest(raw_data)
