"""Versioned experiment records and paired, deterministic schedules."""

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from pathlib import Path
import platform
import re

from ..agent.models import GenerationSettings, Method, RunLimits
from ..agent.prompts import PROMPT_VERSION
from ..audit import AUDIT_SCHEMA_VERSION
from ..gateway import PolicyMode, tool_schemas
from ..gateway.models import POLICY_VERSION
from ..sandbox import SandboxEnvironment
from ..scenarios.catalogue import CASES, MANIFEST_VERSION
from ..scenarios.evidence import fixture_fingerprint
from .permissions import permission_candidates


PROTOCOL_VERSION = "normal-evaluation-v1"
GROUND_TRUTH_VERSION = "phase7-task-contract-v1"
RUBRIC_VERSION = "normal-completion-v1"
MODEL_TAG = "qwen3:4b-instruct-2507-q4_K_M"
MODEL_DIGEST = "0edcdef34593eac1aa2be9c7d06c432dcf81945adca5eca2f27662c18f168ba0"
OLLAMA_VERSION = "0.40.19"
CONTEXT_LENGTH = 4096
NORMAL_CASES = tuple(case.case_id for case in CASES.values() if case.methods)


@dataclass(frozen=True, slots=True)
class Trial:
    trial_id: str
    order: int
    case: str
    policy: PolicyMode
    method: Method
    repetition: int
    seed: int
    condition: str


@dataclass(frozen=True, slots=True)
class Manifest:
    experiment_id: str
    code_revision: str
    profile: str
    protocol_version: str
    case_manifest_version: int
    cases: tuple[tuple[str, int, str, str], ...]
    tool_schema_fingerprint: str
    prompt_version: str
    policy_version: str
    audit_schema_version: int
    ground_truth_version: str
    rubric_version: str
    model_config: tuple[tuple[str, object], ...]
    execution_platform: tuple[tuple[str, str], ...]
    settings: GenerationSettings
    limits: RunLimits
    unsupported: tuple[tuple[str, str], ...]
    missing_rules: tuple[str, ...]
    permission_candidates: tuple[str, ...]
    trials: tuple[Trial, ...]

    def serialise(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"

    def fixture(self, case_id: str) -> str:
        return next(digest for case, _, _, digest in self.cases if case == case_id)


def make_schedule(profile: str = "experiment") -> tuple[Trial, ...]:
    if profile not in {"experiment", "validation", "pilot"}:
        raise ValueError("Unknown schedule profile.")
    trials = []
    methods = (Method.LLM,) if profile == "pilot" else (Method.REPLAY, Method.STUB)
    if profile == "experiment":
        methods = (*methods, Method.LLM)
    cases = ("N1",) if profile == "pilot" else NORMAL_CASES
    policies = tuple(PolicyMode)
    for method in methods:
        repetitions = 10 if method is Method.LLM and profile == "experiment" else 1
        for repetition in range(repetitions):
            for index, case in enumerate(cases):
                offset = (repetition + index) % len(policies)
                for policy in (*policies[offset:], *policies[:offset]):
                    identity = f"{profile}-{method}-{case}-{policy}-{repetition + 1:02d}"
                    trials.append(Trial(identity, len(trials) + 1, case, policy, method, repetition + 1,
                                        42 + repetition, "normal"))
    return tuple(trials)


def make_manifest(experiment_id: str, revision: str, profile: str) -> Manifest:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", experiment_id):
        raise ValueError("Invalid experiment ID.")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("A full Git revision is required.")
    schema_hash = sha256(json.dumps(tool_schemas(), sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    cases = tuple((case.case_id, case.version, case.fixture, fixture_fingerprint(SandboxEnvironment(case.fixture).snapshot()))
                  for case in (CASES[case_id] for case_id in NORMAL_CASES))
    model = (("tag", MODEL_TAG), ("digest", MODEL_DIGEST), ("version", OLLAMA_VERSION),
             ("format", "gguf"), ("quantisation", "Q4_K_M"), ("installed_bytes", 2497293803),
             ("host", "127.0.0.1:11434"), ("cloud_disabled", True), ("context_length", CONTEXT_LENGTH),
             ("parallel_requests", 1), ("expected_processor", "CPU"),
             ("reference_hardware", "Intel i9-13900H, 14 cores/20 threads, 16 GiB RAM, Intel Iris Xe"))
    execution_platform = (("os", platform.system()), ("os_version", platform.version()),
                          ("machine", platform.machine()), ("python", platform.python_version()))
    return Manifest(
        experiment_id, revision, profile, PROTOCOL_VERSION, MANIFEST_VERSION, cases, schema_hash, PROMPT_VERSION,
        POLICY_VERSION, AUDIT_SCHEMA_VERSION, GROUND_TRUTH_VERSION, RUBRIC_VERSION, model, execution_platform,
        GenerationSettings(), RunLimits(),
        tuple((case_id, "scenario execution unsupported") for case_id in CASES if not CASES[case_id].methods),
        ("Unconfirmed decisions and effects are missing evidence.", "Pending reviews are unevaluable.",
         "Interrupted trials are retained without automatic retry.", "Unsupported attack metrics are N/A."),
        permission_candidates(), make_schedule(profile),
    )


def load_manifest(path: Path) -> Manifest:
    def unique_fields(pairs):
        fields = dict(pairs)
        if len(fields) != len(pairs):
            raise ValueError("Duplicate fields in experiment manifest.")
        return fields

    raw = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_fields)
    if not isinstance(raw, dict) or any(type(raw.get(key)) is not str
                                        for key in ("experiment_id", "code_revision", "profile")):
        raise ValueError("Invalid experiment manifest.")
    manifest = make_manifest(raw["experiment_id"], raw["code_revision"], raw["profile"])
    if json.dumps(raw, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n" != manifest.serialise():
        raise ValueError("Manifest differs from the frozen protocol or execution environment.")
    return manifest
