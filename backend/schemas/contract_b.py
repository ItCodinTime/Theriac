# Pydantic model for Contract B: the agent decision schema sent to the Firewall API and rendered as the Incident Memo on the UI.

from typing import Literal

from pydantic import BaseModel, Field


class FirewallRule(BaseModel):
    port: int = Field(ge=1, le=65535)
    action: Literal["ALLOW", "DENY"]


class ContractB(BaseModel):
    target_vpc_id: str
    firewall_rules: list[FirewallRule]
    confidence_score: int = Field(ge=0, le=100)
    cve_flagged: str
    memo_text: str
