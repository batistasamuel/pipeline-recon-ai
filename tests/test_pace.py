import unittest
from unittest.mock import patch

from recon_ai.job import JobError, normalize_spec
from recon_ai.pace import Pace, PaceError, coerce_ai_delay_ms, coerce_cloud_mode


class PaceTests(unittest.TestCase):
    def test_defaults_and_bounds(self):
        self.assertEqual(coerce_ai_delay_ms(None), 2000)
        self.assertEqual(coerce_ai_delay_ms(10), 10)
        self.assertEqual(coerce_ai_delay_ms(600000), 600000)
        with self.assertRaises(PaceError):
            coerce_ai_delay_ms(9)
        with self.assertRaises(PaceError):
            coerce_ai_delay_ms(600001)
        self.assertEqual(coerce_cloud_mode(None), "sequential")
        self.assertEqual(coerce_cloud_mode("PARALLEL"), "parallel")
        with self.assertRaises(PaceError):
            coerce_cloud_mode("round-robin")

    def test_spec_rejects_invalid_delay_and_mode(self):
        spec = normalize_spec({"target": "example.com"})
        self.assertEqual(spec["ai_delay_ms"], 2000)
        self.assertEqual(spec["cloud_mode"], "sequential")
        with self.assertRaises(JobError):
            normalize_spec({"target": "example.com", "ai_delay_ms": 5})
        with self.assertRaises(JobError):
            normalize_spec({"target": "example.com", "cloud_mode": "both"})

    def test_waits_after_first_mark(self):
        pace = Pace(2500)
        with patch("recon_ai.pace.time.sleep") as slept:
            pace.wait()
            slept.assert_not_called()
        pace._local.last = 100.0
        with patch("recon_ai.pace.time.monotonic", return_value=100.0):
            with patch("recon_ai.pace.time.sleep") as slept:
                pace.wait()
        slept.assert_called_once()
        self.assertAlmostEqual(slept.call_args[0][0], 2.5)


if __name__ == "__main__":
    unittest.main()
