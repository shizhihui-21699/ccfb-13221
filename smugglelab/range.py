"""Run every lab scenario through both detectors and score against ground truth."""

from __future__ import annotations

import time
from dataclasses import dataclass

from . import scenarios as S
from .engine import Finding, Target, run_campaign
from .instrumented import TemplateVerdict, diff_all
from .lab import Lab

__all__ = ["ScenarioRun", "MatrixReport", "run_scenario", "run_matrix"]


@dataclass
class ScenarioRun:
    scenario: S.Scenario
    blackbox: Finding | None
    instrumented: list[TemplateVerdict]
    lab_info: dict
    error: str | None = None

    @property
    def detected_blackbox(self) -> set[str]:
        if not self.blackbox:
            return set()
        return {r.key for r in self.blackbox.vulnerable_results}

    @property
    def detected_instrumented(self) -> set[str]:
        return {v.key for v in self.instrumented if v.desync}

    @property
    def fp_blackbox(self) -> set[str]:
        return self.detected_blackbox - set(self.scenario.expected_blackbox)

    @property
    def fn_blackbox(self) -> set[str]:
        return set(self.scenario.expected_blackbox) - self.detected_blackbox

    @property
    def fp_instrumented(self) -> set[str]:
        return self.detected_instrumented - set(self.scenario.expected_instrumented)

    @property
    def fn_instrumented(self) -> set[str]:
        return set(self.scenario.expected_instrumented) - self.detected_instrumented

    def as_dict(self) -> dict:
        return {
            "scenario": self.scenario.key,
            "title": self.scenario.title,
            "story": self.scenario.story,
            "front": self.scenario.front,
            "back": self.scenario.back,
            "consistent": self.scenario.consistent,
            "lab": self.lab_info,
            "expected_blackbox": list(self.scenario.expected_blackbox),
            "detected_blackbox": sorted(self.detected_blackbox),
            "expected_instrumented": list(self.scenario.expected_instrumented),
            "detected_instrumented": sorted(self.detected_instrumented),
            "fp_blackbox": sorted(self.fp_blackbox),
            "fn_blackbox": sorted(self.fn_blackbox),
            "fp_instrumented": sorted(self.fp_instrumented),
            "fn_instrumented": sorted(self.fn_instrumented),
            "error": self.error,
            "blackbox_finding": self.blackbox.as_dict() if self.blackbox else None,
            "instrumented": [v.as_dict() for v in self.instrumented],
        }


@dataclass
class MatrixReport:
    runs: list[ScenarioRun]
    started: float
    finished: float
    trials: int

    @property
    def fp_blackbox(self) -> int:
        return sum(len(r.fp_blackbox) for r in self.runs)

    @property
    def fn_blackbox(self) -> int:
        return sum(len(r.fn_blackbox) for r in self.runs)

    @property
    def fp_instrumented(self) -> int:
        return sum(len(r.fp_instrumented) for r in self.runs)

    @property
    def fn_instrumented(self) -> int:
        return sum(len(r.fn_instrumented) for r in self.runs)

    @property
    def total_expected_blackbox(self) -> int:
        return sum(len(r.scenario.expected_blackbox) for r in self.runs)

    @property
    def total_detected_blackbox(self) -> int:
        return sum(len(r.detected_blackbox) for r in self.runs)

    def as_dict(self) -> dict:
        return {
            "started": self.started,
            "finished": self.finished,
            "duration": round(self.finished - self.started, 3),
            "trials": self.trials,
            "summary": {
                "scenarios": len(self.runs),
                "blackbox": {
                    "expected": self.total_expected_blackbox,
                    "detected": self.total_detected_blackbox,
                    "false_positives": self.fp_blackbox,
                    "false_negatives": self.fn_blackbox,
                },
                "instrumented": {
                    "expected": sum(len(r.scenario.expected_instrumented) for r in self.runs),
                    "detected": sum(len(r.detected_instrumented) for r in self.runs),
                    "false_positives": self.fp_instrumented,
                    "false_negatives": self.fn_instrumented,
                },
            },
            "runs": [r.as_dict() for r in self.runs],
        }


def run_scenario(scenario: S.Scenario, *, trials: int = 3, victim_len: int = 96,
                 blackbox_keys: list[str] | None = None) -> ScenarioRun:
    try:
        with Lab(scenario.lab_config()) as lab:
            target = Target("127.0.0.1", lab.front_port, label=scenario.key)
            finding = run_campaign(target, keys=blackbox_keys, trials=trials,
                                   victim_len=victim_len)
            finding.meta["lab"] = lab.info()
            lab.reset()
            verdicts = diff_all(lab)
            info = lab.info()
        return ScenarioRun(
            scenario=scenario,
            blackbox=finding,
            instrumented=verdicts,
            lab_info=info,
        )
    except Exception as e:
        return ScenarioRun(
            scenario=scenario,
            blackbox=None,
            instrumented=[],
            lab_info={},
            error=f"{type(e).__name__}: {e}",
        )


def run_matrix(*, keys: list[str] | None = None, trials: int = 3,
               victim_len: int = 96) -> MatrixReport:
    scen = S.SCENARIOS
    if keys:
        scen = [S.SCENARIOS_BY_KEY[k] for k in keys if k in S.SCENARIOS_BY_KEY]
    started = time.time()
    runs = [run_scenario(s, trials=trials, victim_len=victim_len) for s in scen]
    finished = time.time()
    return MatrixReport(runs=runs, started=started, finished=finished, trials=trials)
