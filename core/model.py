from dataclasses import dataclass

@dataclass(frozen=True)
class GuardDecision:
    decision: str      # "ALLOW" | "BLOCK"
    confidence: float  # 0..1
    rationale: str     # short explanation
