"""Shared locked constants for the development implementation."""

DEVELOPMENT_LABEL = (
    "EXPLORATORY_DEVELOPMENT_ONLY — NOT CALIBRATION — NOT LOCKED — "
    "NOT MANUSCRIPT EVIDENCE"
)

PUBLIC_MOCK_ROLE_LABEL = (
    "PUBLIC_MOCK_ROLE_ONLY — NOT CALIBRATION — NOT LOCKED EVIDENCE"
)

CONFIRMATORY_MOCK_ENGINE_SCOPE = "CONFIRMATORY_ENGINE_PUBLIC_MOCK_DRY_RUN"
ENGINEERING_FIXTURE_SCOPE = "UNIT_OR_ENGINEERING_FIXTURE_ONLY"

TERMINAL_STATUSES = frozenset(
    {
        "EXECUTED",
        "INVALID_SYNTAX",
        "INVALID_SEMANTICS",
        "RESOURCE_TIMEOUT",
        "RESOURCE_MEMORY",
        "NUMERICAL_FAILURE",
        "CANONICAL_DUPLICATE",
    }
)

BENCHMARK_SUB_IDS = ("A0", "A1", "B0", "B1", "C", "D0", "D1", "D2", "E", "F0")
ERROR_SOURCES = (
    "rule/model",
    "parameter",
    "initial-state",
    "stochastic",
    "numerical",
    "coarse-graining",
    "measurement/interface",
)
