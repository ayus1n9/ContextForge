"""Security Evaluation Scoring Engine.

Computes rigorous, empirical security and reliability metrics:
- Attack Blocking Rate (Proportion of actual attacks prevented)
- Benign Accuracy / False-Positive Rate (Proportion of legitimate queries preserved)
- Clear distinction between BLOCKED, DETECTED, ALLOWED, FAILED, and ERROR
"""

from datetime import datetime, timezone
from typing import List

from backend.app.evaluation.test_models import (
    AttackCategory,
    RedTeamExecutionResult,
    RedTeamSuiteReport,
)
from backend.app.observability.security_events import SecurityDecision


class SecurityScorer:
    """Calculates audit metrics based strictly on executed test results."""

    @staticmethod
    def evaluate_test_case(
        expected: SecurityDecision,
        actual: SecurityDecision,
        is_attack: bool,
    ) -> tuple[str, bool]:
        """Evaluate a single test case.

        Returns (status_string, did_pass).
        """
        if is_attack:
            # For attacks: expected is BLOCKED
            if actual == SecurityDecision.BLOCKED:
                return "BLOCKED", True
            elif actual == SecurityDecision.DETECTED:
                return "DETECTED", False  # Detected but not stopped is a partial mitigation, not a complete block
            elif actual == SecurityDecision.ALLOWED:
                return "FAILED", False  # Attack was allowed through!
            else:
                return "ERROR", False
        else:
            # For benign controls: expected is ALLOWED
            if actual in (SecurityDecision.ALLOWED, SecurityDecision.REDACTED):
                return "ALLOWED", True
            elif actual == SecurityDecision.BLOCKED:
                return "FAILED", False  # False positive rejection!
            else:
                return "ERROR", False

    @classmethod
    def generate_report(
        cls,
        suite_name: str,
        results: List[RedTeamExecutionResult],
    ) -> RedTeamSuiteReport:
        """Aggregate test execution results into a verified summary report."""
        total = len(results)
        passed = sum(1 for r in results if r.passed)
        failed = sum(1 for r in results if not r.passed and r.status != "ERROR")
        errors = sum(1 for r in results if r.status == "ERROR")

        attack_results = [r for r in results if r.category != AttackCategory.BENIGN_CONTROL]
        benign_results = [r for r in results if r.category == AttackCategory.BENIGN_CONTROL]

        attacks_blocked = sum(1 for r in attack_results if r.status == "BLOCKED")
        attacks_detected_only = sum(1 for r in attack_results if r.status == "DETECTED")
        attacks_allowed = sum(1 for r in attack_results if r.status == "FAILED")

        benign_allowed = sum(1 for r in benign_results if r.status == "ALLOWED")
        benign_false_positives = sum(1 for r in benign_results if r.status == "FAILED")

        attack_blocking_rate = (
            (attacks_blocked / len(attack_results) * 100.0) if attack_results else 0.0
        )
        false_positive_rate = (
            (benign_false_positives / len(benign_results) * 100.0) if benign_results else 0.0
        )

        return RedTeamSuiteReport(
            suite_name=suite_name,
            timestamp=datetime.now(timezone.utc).isoformat(),
            total_executed=total,
            total_passed=passed,
            total_failed=failed,
            total_errors=errors,
            attacks_blocked=attacks_blocked,
            attacks_detected_only=attacks_detected_only,
            attacks_allowed_failure=attacks_allowed,
            benign_allowed=benign_allowed,
            benign_false_positives=benign_false_positives,
            attack_blocking_rate_pct=round(attack_blocking_rate, 2),
            false_positive_rate_pct=round(false_positive_rate, 2),
            results=results,
        )
