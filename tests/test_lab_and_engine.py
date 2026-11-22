"""End-to-end tests: the lab, the black-box engine and the instrumented diff.

These spin up real loopback sockets, so they take a few seconds.
"""

from __future__ import annotations

import unittest

from smugglelab import dialects as D
from smugglelab import scenarios as S
from smugglelab.engine import Target, run_campaign
from smugglelab.instrumented import diff_all
from smugglelab.lab import Lab, LabConfig
from smugglelab.probe import run_probe
from smugglelab.templates import TEMPLATES_BY_KEY


class LabSmoke(unittest.TestCase):
    def test_clean_request_roundtrips(self):
        with Lab(LabConfig(D.NGINX, D.PYTHON_ORIGIN)) as lab:
            run = run_probe(
                "127.0.0.1", lab.front_port,
                [b"GET /__lab/echo/HELLO HTTP/1.1\r\nHost: x\r\n\r\n"],
                read_timeout=0.5, idle_gap=0.08,
            )
            self.assertTrue(run.responses)
            self.assertEqual(run.responses[0].status, 200)
            self.assertIn("HELLO", run.responses[0].body_text())


class BlackBoxDetection(unittest.TestCase):
    """The oracle must confirm known-bad pairs and stay silent on matched ones."""

    def test_cl_te_pair_confirms_cl_te(self):
        with Lab(LabConfig(D.LEGACY_LB, D.JAVA_ORIGIN)) as lab:
            f = run_campaign(Target("127.0.0.1", lab.front_port), keys=["cl_te"], trials=2)
            self.assertTrue(f.results[0].vulnerable)
            self.assertEqual(f.results[0].reproductions, 2)

    def test_te_cl_pair_confirms_te_cl(self):
        with Lab(LabConfig(D.APACHE_PROXY, D.NODE_ORIGIN)) as lab:
            f = run_campaign(Target("127.0.0.1", lab.front_port), keys=["te_cl"], trials=2)
            self.assertTrue(f.results[0].vulnerable)

    def test_te_te_pair_confirms_te_te(self):
        with Lab(LabConfig(D.TE_FALLBACK, D.TE_FIRST_ONLY)) as lab:
            f = run_campaign(Target("127.0.0.1", lab.front_port), keys=["te_te"], trials=2)
            self.assertTrue(f.results[0].vulnerable)

    def test_matched_pair_stays_silent(self):
        for front, back in [
            (D.NGINX, D.PYTHON_ORIGIN),
            (D.ENVOY, D.GO_ORIGIN),
            (D.LOOSE_PROXY, D.LEGACY_ORIGIN),
        ]:
            with self.subTest(front=front.name, back=back.name):
                with Lab(LabConfig(front, back)) as lab:
                    f = run_campaign(Target("127.0.0.1", lab.front_port), trials=2)
                    self.assertEqual(f.vulnerable_results, [])

    def test_control_is_clean_for_vulnerable_pair(self):
        with Lab(LabConfig(D.LEGACY_LB, D.JAVA_ORIGIN)) as lab:
            f = run_campaign(Target("127.0.0.1", lab.front_port), keys=["cl_te"], trials=2)
            self.assertFalse(f.results[0].control.leaked_nonce)


class InstrumentedDiff(unittest.TestCase):
    def test_matched_pair_has_no_diffs(self):
        with Lab(LabConfig(D.NGINX, D.PYTHON_ORIGIN)) as lab:
            verdicts = diff_all(lab)
            self.assertEqual([v.key for v in verdicts if v.desync], [])

    def test_cl_te_pair_shows_cl_te_diff(self):
        with Lab(LabConfig(D.LEGACY_LB, D.JAVA_ORIGIN)) as lab:
            verdicts = {v.key: v for v in diff_all(lab)}
            self.assertTrue(verdicts["cl_te"].desync)

    def test_every_template_is_exercised(self):
        with Lab(LabConfig(D.LEGACY_LB, D.JAVA_ORIGIN)) as lab:
            verdicts = diff_all(lab)
            self.assertEqual(len(verdicts), len(TEMPLATES_BY_KEY))


class ScenarioMatrix(unittest.TestCase):
    """The end-to-end self-check: zero false positives and negatives."""

    def test_full_matrix_matches_ground_truth(self):
        from smugglelab.range import run_matrix

        report = run_matrix(trials=2)
        for run in report.runs:
            with self.subTest(scenario=run.scenario.key):
                self.assertIsNone(run.error)
                self.assertEqual(run.fp_blackbox, set())
                self.assertEqual(run.fn_blackbox, set())
                self.assertEqual(run.fp_instrumented, set())
                self.assertEqual(run.fn_instrumented, set())


class Samples(unittest.TestCase):
    def test_sample_replay_is_valid_python(self):
        from smugglelab.samples import build_sample

        for key in ("cl_te", "te_cl", "cl_cl", "te_te"):
            with self.subTest(shape=key):
                sample = build_sample(key)
                compile(sample.python_replay(), "<sample>", "exec")
                self.assertIn(b"SMUGGLE_MARKER", sample.request)


if __name__ == "__main__":
    unittest.main()
