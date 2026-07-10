# Pydantic model for Contract A: the extraction output schema pushed from the PDF parser to the Vultr Vector Store.

from typing import Literal

from pydantic import BaseModel, Field


class AllowedPort(BaseModel):
    port: int = Field(ge=1, le=65535)
    protocol: Literal["TCP", "UDP"]
    reason: str = Field(min_length=1)


class ContractA(BaseModel):
    device_model: str = Field(min_length=1)
    firmware_version: str = Field(min_length=1)
    allowed_ports: list[AllowedPort]
    source_doc_id: str
