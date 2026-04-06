"""
Vektor AI — Tier 2 Policy Engine

Suggest → Approve → Learn loop for customer-specific policies.
Tier 2 is a Day 1 feature. Vektor analyzes the customer environment,
surfaces suggested policies, customer approves/dismisses, and the platform
learns from feedback. Enough cross-customer approvals → graduates to Tier 1.
"""

from .engine import PolicyEngine, Policy, PolicyStatus, PolicyScope
from .suggestions import PolicySuggestionGenerator, Suggestion, SuggestionReason

__all__ = [
    "PolicyEngine",
    "Policy",
    "PolicyStatus",
    "PolicyScope",
    "PolicySuggestionGenerator",
    "Suggestion",
    "SuggestionReason",
]
