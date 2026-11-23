"""
AgentShield AI — Structured Policy Condition Validator (Phase 10).

Evaluates structured declarative conditions WITHOUT any eval(), exec(),
or arbitrary Python code execution.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Tuple, Union

logger = logging.getLogger("agentshield.security.condition_validator")

# Supported safe operators
ALLOWED_OPERATORS = {
    "equals", "==", "eq",
    "not_equals", "!=", "neq",
    "contains",
    "not_contains",
    "in",
    "not_in",
    "starts_with",
    "ends_with",
    "greater_than", ">", "gt",
    "less_than", "<", "lt",
    "greater_than_or_equal", ">=", "gte",
    "less_than_or_equal", "<=", "lte",
    "matches_pattern", "regex",
}


def _extract_field_value(field_path: str, context: Dict[str, Any]) -> Any:
    """Extract nested value from context dictionary (e.g., 'arguments.path' or 'resource')."""
    if not field_path:
        return None

    parts = field_path.strip().split(".")
    curr: Any = context
    for part in parts:
        if isinstance(curr, dict):
            curr = curr.get(part)
        elif hasattr(curr, part):
            curr = getattr(curr, part)
        else:
            return None
        if curr is None:
            return None
    return curr


def validate_conditions_syntax(conditions: Union[str, List[Dict[str, Any]], Dict[str, Any]]) -> Tuple[bool, str | None]:
    """
    Validate that structured condition objects adhere to allowed schemas.
    Rejects any attempts to inject executable code or unknown operators.
    """
    import json
    if isinstance(conditions, str):
        try:
            parsed = json.loads(conditions)
            conditions = parsed
        except Exception as e:
            return False, f"Invalid JSON format: {e}"

    cond_list = conditions if isinstance(conditions, list) else [conditions]

    for idx, cond in enumerate(cond_list):
        if not isinstance(cond, dict):
            return False, f"Condition at index {idx} must be a JSON object."

        op = cond.get("operator")
        if not op:
            return False, f"Condition at index {idx} is missing required 'operator' field."

        op_norm = str(op).lower()
        if op_norm not in ALLOWED_OPERATORS:
            return False, f"Condition at index {idx} specifies unsupported operator '{op}'."

        field_name = cond.get("field")
        if not field_name or not isinstance(field_name, str):
            return False, f"Condition at index {idx} is missing required string 'field'."

        # Prevent dunder access or suspicious injection
        if "__" in field_name or "(" in field_name or ";" in field_name:
            return False, f"Condition at index {idx} contains illegal characters in field name."

        if "value" not in cond:
            return False, f"Condition at index {idx} is missing required 'value' field."

        if op_norm in ("matches_pattern", "regex"):
            pattern = cond.get("value")
            if not isinstance(pattern, str):
                return False, f"Pattern for regex condition {idx} must be a string."
            try:
                re.compile(pattern)
            except re.error as e:
                return False, f"Invalid regex pattern in condition {idx}: {e}"

    return True, None


def evaluate_single_condition(cond: Dict[str, Any], context: Dict[str, Any]) -> bool:
    """Safely evaluate a single structured condition against context without eval/exec."""
    field_path = cond.get("field", "")
    op = str(cond.get("operator", "")).lower()
    target_val = cond.get("value")

    actual_val = _extract_field_value(field_path, context)
    if actual_val is None:
        # If field is missing, equality checks against None might match
        if op in ("equals", "==", "eq") and target_val is None:
            return True
        return False

    try:
        if op in ("equals", "==", "eq"):
            return actual_val == target_val

        elif op in ("not_equals", "!=", "neq"):
            return actual_val != target_val

        elif op == "contains":
            if isinstance(actual_val, (str, list, dict, set, tuple)):
                return target_val in actual_val
            return False

        elif op == "not_contains":
            if isinstance(actual_val, (str, list, dict, set, tuple)):
                return target_val not in actual_val
            return True

        elif op == "in":
            if isinstance(target_val, (list, tuple, set)):
                return actual_val in target_val
            elif isinstance(target_val, str) and isinstance(actual_val, str):
                return actual_val in target_val
            return False

        elif op == "not_in":
            if isinstance(target_val, (list, tuple, set)):
                return actual_val not in target_val
            elif isinstance(target_val, str) and isinstance(actual_val, str):
                return actual_val not in target_val
            return True

        elif op == "starts_with":
            if isinstance(actual_val, str) and isinstance(target_val, str):
                return actual_val.startswith(target_val)
            return False

        elif op == "ends_with":
            if isinstance(actual_val, str) and isinstance(target_val, str):
                return actual_val.endswith(target_val)
            return False

        elif op in ("greater_than", ">", "gt"):
            return float(actual_val) > float(target_val)

        elif op in ("less_than", "<", "lt"):
            return float(actual_val) < float(target_val)

        elif op in ("greater_than_or_equal", ">=", "gte"):
            return float(actual_val) >= float(target_val)

        elif op in ("less_than_or_equal", "<=", "lte"):
            return float(actual_val) <= float(target_val)

        elif op in ("matches_pattern", "regex"):
            if isinstance(actual_val, str) and isinstance(target_val, str):
                return bool(re.search(target_val, actual_val))
            return False

    except (ValueError, TypeError) as exc:
        logger.debug("Condition evaluation type mismatch: %s", exc)
        return False

    return False


def evaluate_conditions(
    conditions: Union[List[Dict[str, Any]], Dict[str, Any], None],
    context: Dict[str, Any],
) -> bool:
    """
    Evaluate a set of structured conditions (ALL must match, logical AND).
    Empty conditions list returns True.
    """
    if not conditions:
        return True

    cond_list = conditions if isinstance(conditions, list) else [conditions]
    for cond in cond_list:
        if not evaluate_single_condition(cond, context):
            return False
    return True
