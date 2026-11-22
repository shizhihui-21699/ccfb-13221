"""End-to-end test: spin up selected lab pairs and verify the engine's
verdicts against the scenario expectations."""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lab.backend import CanaryStore, LabBackend
from lab.parser import PROFILES
from lab.proxy import LabProxy
from lab.scenarios import SCENARIOS
from smuggler.detector import EngineConfig, Target, scan


class EndToEnd(unittest.TestCase):
    procs = []

    @classmethod
    def setUpClass(cls):
        cls.store = CanaryStore()
        cls.backends = []
        cls.proxies = []
        for sc in SCENARIOS:
            be = LabBackend(sc.backend_port, PROFILES[sc.backend_profile],
                            cls.store, read_timeout=4.0)
            be.start()
            cls.backends.append(be)
        time.sleep(0.2)
        for sc in SCENARIOS:
            px = LabProxy(sc.proxy_port, sc.backend_port,
                          PROFILES[sc.proxy_profile], read_timeout=4.0)
            px.start()
            cls.proxies.append(px)
        time.sleep(0.4)

    @classmethod
    def tearDownClass(cls):
        for px in cls.proxies:
            px.stop()
        for be in cls.backends:
            be.stop()

    def _scan(self, scenario_name, families):
        sc = next(s for s in SCENARIOS if s.name == scenario_name)
        cfg = EngineConfig(timeout=4.0, linger=0.25, timing_repeats=3,
                           timing_floor=1.0, baseline_samples=4)
        return scan(Target("127.0.0.1", sc.proxy_port), cfg,
                    variant_filter=families)

    def test_clean_pair_reports_no_vulnerable(self):
        result = self._scan("strict-strict",
                            ["CL.TE", "TE.CL", "TE.TE", "CL.CL"])
        self.assertEqual(result["counts"]["VULNERABLE"], 0,
                         msg=f"clean target flagged: {result['counts']}")

    def test_hardened_pair_reports_no_vulnerable(self):
        result = self._scan("hardened-hardened",
                            ["CL.TE", "TE.CL", "TE.TE", "CL.CL"])
        self.assertEqual(result["counts"]["VULNERABLE"], 0)

    def test_consistent_lenient_pair_reports_no_vulnerable(self):
        result = self._scan("lenientte-lenientte",
                            ["CL.TE", "TE.CL", "TE.TE", "CL.CL"])
        self.assertEqual(result["counts"]["VULNERABLE"], 0)

    def test_te_obfuscation_fallback_is_smuggable(self):
        # Strict front-end falls back to CL on obfuscated TE while the
        # lenient back-end honors chunked -> CL.TE via TE obfuscation.
        result = self._scan("te-obfuscation-fallback", ["CL.TE"])
        self.assertGreaterEqual(result["counts"]["VULNERABLE"], 1)

    def test_clte_scenario_detected(self):
        result = self._scan("clte-lenient-te", ["CL.TE"])
        self.assertGreaterEqual(result["counts"]["VULNERABLE"], 1,
                                msg=str(result["counts"]))

    def test_tecl_scenario_detected(self):
        result = self._scan("tecl-lenient-cl", ["TE.CL"])
        self.assertGreaterEqual(result["counts"]["VULNERABLE"], 1,
                                msg=str(result["counts"]))

    def test_tete_scenario_detected(self):
        result = self._scan("tete-order-diff", ["TE.TE"])
        self.assertGreaterEqual(
            result["counts"]["VULNERABLE"]
            + result["counts"]["SUSPICIOUS"], 1,
            msg=str(result["counts"]))

    def test_clcl_scenario_detected(self):
        result = self._scan("clcl-dup-diff", ["CL.CL"])
        self.assertGreaterEqual(
            result["counts"]["VULNERABLE"]
            + result["counts"]["SUSPICIOUS"], 1,
            msg=str(result["counts"]))

    def test_every_result_has_evidence_or_rejection_note(self):
        result = self._scan("strict-strict", ["CL.TE"])
        for row in result["results"]:
            self.assertTrue(row["evidence"] or row["error"])


if __name__ == "__main__":
    unittest.main()
