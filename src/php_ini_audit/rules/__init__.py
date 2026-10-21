"""Importing the rule modules registers every rule in REGISTRY."""

from . import disclosure, execution, extensions, filesystem, hygiene, resources, server, session  # noqa: F401
from .base import CATEGORIES, REGISTRY, Context, FileContext, Hit, Rule

__all__ = ["CATEGORIES", "REGISTRY", "Context", "FileContext", "Hit", "Rule"]
