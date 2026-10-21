"""Importing the rule modules registers every rule in REGISTRY."""

from . import (  # noqa: F401
    disclosure,
    execution,
    extensions,
    filesystem,
    hygiene,
    resources,
    server,
    session,
    vulnerabilities,
)
from .base import CATEGORIES, REGISTRY, Context, FileContext, Hit, Rule

__all__ = ["CATEGORIES", "REGISTRY", "Context", "FileContext", "Hit", "Rule"]
