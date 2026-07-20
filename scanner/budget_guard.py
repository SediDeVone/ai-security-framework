"""Agent Budget & Token Quota Manager (Denial of Wallet Mitigation).

Enforces cost caps, max iterations, and token quotas per agent session
to prevent runaway agent loops, infinite recursion, and LLM Jacking.
Reference: OWASP LLM10 Unbounded Consumption / AI Security Standards.
"""
import time
from typing import Optional


class BudgetExceededException(Exception):
    pass


class AgentBudgetGuard:
    def __init__(self, max_cost_usd: float = 1.0, max_tokens: int = 100_000, max_steps: int = 15):
        self.max_cost_usd = max_cost_usd
        self.max_tokens = max_tokens
        self.max_steps = max_steps
        
        self.current_tokens = 0
        self.current_steps = 0
        self.estimated_cost_usd = 0.0

    def record_step(self, tokens_used: int, estimated_cost: float = 0.0):
        """Records a step execution and validates against budget thresholds."""
        self.current_steps += 1
        self.current_tokens += tokens_used
        self.estimated_cost_usd += estimated_cost

        if self.current_steps > self.max_steps:
            raise BudgetExceededException(
                f"MAX STEPS EXCEEDED: Agent reached limit of {self.max_steps} steps. Loop terminated."
            )

        if self.current_tokens > self.max_tokens:
            raise BudgetExceededException(
                f"TOKEN QUOTA EXCEEDED: Used {self.current_tokens} tokens (Limit: {self.max_tokens})."
            )

        if self.estimated_cost_usd > self.max_cost_usd:
            raise BudgetExceededException(
                f"BUDGET CAP EXCEEDED: Session cost ${self.estimated_cost_usd:.4f} exceeded limit of ${self.max_cost_usd:.2f}."
            )

    def get_summary(self) -> dict:
        return {
            "steps_taken": self.current_steps,
            "tokens_consumed": self.current_tokens,
            "cost_usd": round(self.estimated_cost_usd, 4),
            "max_steps": self.max_steps,
            "max_tokens": self.max_tokens,
            "max_cost_usd": self.max_cost_usd
        }
