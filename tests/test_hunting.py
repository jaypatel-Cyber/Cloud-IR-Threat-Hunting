#!/usr/bin/env python3
# Author: Jay Patel
"""
Unit and integration tests for the Cloud IR & Threat Hunting pipeline.

Tests cover:
  - CloudTrail record flattening (ingestor)
  - DataFrame construction from raw records
  - All six anomaly detection modules
  - IP profiler output structure
  - End-to-end orchestration smoke test

Runnable without pytest:  python test_hunting.py
Also compatible with:     pytest tests/test_hunting.py -v
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

import pandas as pd

# Ensure the hunting module is importable from any working directory
REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "hunting"))

from cloudtrail_ingestor import _flatten_record, build_dataframe, load_from_file
from anomaly_detector import (
    detect_after_hours_activity,
    detect_api_frequency_anomalies,
    detect_creation_bursts,
    detect_error_rate_anomalies,
    detect_rare_api_calls,
    detect_sensitive_api_access,
    run_all_detections,
)
from ip_profiler import profile_ip_json, MITRE_MAP


# ─── Fixtures ─────────────────────────────────────────────────────────────────

ATTACKER_IP = "185.220.101.47"
CORP_IP = "72.21.198.44"
SAMPLE_LOG = str(REPO_ROOT / "sample_data" / "cloudtrail_logs.json")


def _make_record(
    event_name: str = "GetObject",
    event_source: str = "s3.amazonaws.com",
    source_ip: str = CORP_IP,
    region: str = "us-east-1",
    username: str = "alice.johnson",
    error_code: str = None,
    event_time: str = "2024-03-15T10:00:00Z",
) -> dict:
    """Build a minimal synthetic CloudTrail record for testing."""
    return {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDATEST0001",
            "arn": f"arn:aws:iam::123456789012:user/{username}",
            "accountId": "123456789012",
            "userName": username,
        },
        "eventTime": event_time,
        "eventSource": event_source,
        "eventName": event_name,
        "awsRegion": region,
        "sourceIPAddress": source_ip,
        "userAgent": "aws-cli/2.15.12",
        "requestParameters": {"bucketName": "test-bucket"},
        "responseElements": None,
        "errorCode": error_code,
        "errorMessage": "Access Denied" if error_code else None,
        "requestID": "TESTREQUESTID001",
        "eventID": "test-event-id-0001",
        "eventType": "AwsApiCall",
        "recipientAccountId": "123456789012",
    }


def _make_df_from_records(records: list) -> pd.DataFrame:
    return build_dataframe(records)


# ─── Ingestor Tests ───────────────────────────────────────────────────────────

class TestCloudTrailIngestor(unittest.TestCase):

    def test_flatten_basic_iam_user(self):
        rec = _make_record()
        flat = _flatten_record(rec)
        self.assertEqual(flat["eventName"], "GetObject")
        self.assertEqual(flat["eventSource"], "s3.amazonaws.com")
        self.assertEqual(flat["sourceIPAddress"], CORP_IP)
        self.assertEqual(flat["userName"], "alice.johnson")
        self.assertIsNone(flat["errorCode"])

    def test_flatten_with_error(self):
        rec = _make_record(error_code="AccessDenied")
        flat = _flatten_record(rec)
        self.assertEqual(flat["errorCode"], "AccessDenied")

    def test_flatten_assumed_role_identity(self):
        rec = _make_record()
        rec["userIdentity"] = {
            "type": "AssumedRole",
            "principalId": "AROATEST:session",
            "arn": "arn:aws:sts::123456789012:assumed-role/my-role/session",
            "accountId": "123456789012",
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "userName": "my-role",
                }
            },
        }
        flat = _flatten_record(rec)
        self.assertEqual(flat["userName"], "my-role")
        self.assertEqual(flat["userType"], "AssumedRole")

    def test_build_dataframe_shape(self):
        records = [_make_record() for _ in range(5)]
        df = _make_df_from_records(records)
        self.assertEqual(len(df), 5)
        self.assertIn("eventTime", df.columns)
        self.assertIn("sourceIPAddress", df.columns)
        self.assertIn("eventName", df.columns)
        self.assertIn("userName", df.columns)

    def test_build_dataframe_sorted_by_time(self):
        times = ["2024-03-15T12:00:00Z", "2024-03-15T09:00:00Z", "2024-03-15T10:30:00Z"]
        records = [_make_record(event_time=t) for t in times]
        df = _make_df_from_records(records)
        ts = df["eventTime"].tolist()
        self.assertEqual(ts, sorted(ts))

    def test_load_from_file_sample_data(self):
        if not Path(SAMPLE_LOG).exists():
            self.skipTest("sample_data/cloudtrail_logs.json not found")
        records = load_from_file(SAMPLE_LOG)
        self.assertGreater(len(records), 0)
        self.assertIn("eventName", records[0])

    def test_load_from_file_missing_raises_exit(self):
        with self.assertRaises(SystemExit):
            load_from_file("/nonexistent/path/cloudtrail.json")

    def test_load_from_file_json_gz(self):
        import gzip
        records = [_make_record(event_name="DescribeInstances")]
        payload = json.dumps({"Records": records}).encode()
        with tempfile.NamedTemporaryFile(suffix=".json.gz", delete=False) as tf:
            tf.write(gzip.compress(payload))
            tmp_path = tf.name
        try:
            loaded = load_from_file(tmp_path)
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0]["eventName"], "DescribeInstances")
        finally:
            os.unlink(tmp_path)


# ─── Anomaly Detector Tests ───────────────────────────────────────────────────

class TestApiFrequencyDetection(unittest.TestCase):

    def _make_frequency_df(self) -> pd.DataFrame:
        """IP-A: 2 calls (normal). IP-B: 2 calls. IP-C (attacker): 20 calls."""
        records = (
            [_make_record(source_ip="10.0.0.1")] * 2 +
            [_make_record(source_ip="10.0.0.2")] * 2 +
            [_make_record(source_ip=ATTACKER_IP)] * 20
        )
        return _make_df_from_records(records)

    def test_detects_high_volume_ip(self):
        df = self._make_frequency_df()
        result = detect_api_frequency_anomalies(df)
        self.assertFalse(result.empty)
        self.assertIn(ATTACKER_IP, result["sourceIPAddress"].values)

    def test_returns_empty_when_all_normal(self):
        records = [_make_record(source_ip=f"10.0.0.{i}") for i in range(5)]
        df = _make_df_from_records(records)
        result = detect_api_frequency_anomalies(df)
        self.assertTrue(result.empty)

    def test_z_score_column_present(self):
        df = self._make_frequency_df()
        result = detect_api_frequency_anomalies(df)
        self.assertIn("z_score", result.columns)


class TestErrorRateDetection(unittest.TestCase):

    def _make_error_df(self) -> pd.DataFrame:
        normal = [_make_record(source_ip="10.0.0.1") for _ in range(10)]
        # Attacker: 8/10 events are AccessDenied
        attack_err = [_make_record(source_ip=ATTACKER_IP, error_code="AccessDenied") for _ in range(8)]
        attack_ok = [_make_record(source_ip=ATTACKER_IP) for _ in range(2)]
        return _make_df_from_records(normal + attack_err + attack_ok)

    def test_detects_high_error_rate_ip(self):
        df = self._make_error_df()
        result = detect_error_rate_anomalies(df)
        self.assertFalse(result.empty)
        self.assertIn(ATTACKER_IP, result["sourceIPAddress"].values)

    def test_error_rate_column_present(self):
        df = self._make_error_df()
        result = detect_error_rate_anomalies(df)
        self.assertIn("error_rate", result.columns)


class TestRareApiCallDetection(unittest.TestCase):

    def test_detects_stop_logging(self):
        # StopLogging appears once out of many common calls
        records = (
            [_make_record(event_name="GetObject")] * 50 +
            [_make_record(event_name="StopLogging", source_ip=ATTACKER_IP)]
        )
        df = _make_df_from_records(records)
        result = detect_rare_api_calls(df)
        self.assertFalse(result.empty)
        self.assertIn("StopLogging", result["eventName"].values)

    def test_no_rare_calls_returns_empty(self):
        records = [_make_record(event_name="GetObject")] * 20
        df = _make_df_from_records(records)
        result = detect_rare_api_calls(df)
        self.assertTrue(result.empty)


class TestAfterHoursDetection(unittest.TestCase):

    def test_detects_2am_activity(self):
        records = [_make_record(event_time="2024-03-15T02:14:00Z",
                                source_ip=ATTACKER_IP)]
        df = _make_df_from_records(records)
        result = detect_after_hours_activity(df)
        self.assertFalse(result.empty)
        self.assertIn(ATTACKER_IP, result["sourceIPAddress"].values)

    def test_business_hours_not_flagged(self):
        records = [_make_record(event_time="2024-03-15T09:30:00Z")]
        df = _make_df_from_records(records)
        result = detect_after_hours_activity(df)
        self.assertTrue(result.empty)

    def test_aws_service_excluded(self):
        # AWSService type should not trigger after-hours alert
        rec = _make_record(event_time="2024-03-15T03:00:00Z")
        rec["userIdentity"]["type"] = "AWSService"
        df = _make_df_from_records([rec])
        result = detect_after_hours_activity(df)
        self.assertTrue(result.empty)


class TestCreationBurstDetection(unittest.TestCase):

    def test_detects_burst_above_threshold(self):
        records = [
            _make_record(event_name="RunInstances", source_ip=ATTACKER_IP),
            _make_record(event_name="CreateAccessKey", source_ip=ATTACKER_IP),
            _make_record(event_name="CreateSecurityGroup", source_ip=ATTACKER_IP,
                         event_source="ec2.amazonaws.com"),
        ]
        # Patch CreateSecurityGroup into CREATION_EVENTS for this test
        from anomaly_detector import CREATION_EVENTS as CE
        original = set(CE)
        CE |= {"CreateSecurityGroup"}
        try:
            df = _make_df_from_records(records)
            result = detect_creation_bursts(df)
            self.assertFalse(result.empty)
        finally:
            CE.clear()
            CE.update(original)

    def test_below_threshold_not_flagged(self):
        records = [_make_record(event_name="RunInstances", source_ip="10.0.0.1")]
        df = _make_df_from_records(records)
        result = detect_creation_bursts(df)
        self.assertTrue(result.empty)


class TestSensitiveApiDetection(unittest.TestCase):

    def test_detects_assume_role(self):
        rec = _make_record(event_name="AssumeRole", event_source="sts.amazonaws.com",
                           source_ip=ATTACKER_IP)
        df = _make_df_from_records([rec])
        result = detect_sensitive_api_access(df)
        self.assertFalse(result.empty)
        self.assertEqual(result.iloc[0]["eventName"], "AssumeRole")

    def test_detects_stop_logging(self):
        rec = _make_record(event_name="StopLogging",
                           event_source="cloudtrail.amazonaws.com",
                           source_ip=ATTACKER_IP)
        df = _make_df_from_records([rec])
        result = detect_sensitive_api_access(df)
        self.assertFalse(result.empty)

    def test_normal_api_not_flagged(self):
        rec = _make_record(event_name="GetObject")
        df = _make_df_from_records([rec])
        result = detect_sensitive_api_access(df)
        self.assertTrue(result.empty)


class TestRunAllDetections(unittest.TestCase):

    def test_returns_all_six_modules(self):
        records = [_make_record()]
        df = _make_df_from_records(records)
        results = run_all_detections(df)
        expected_keys = {"api_frequency", "error_rate", "rare_api_calls",
                         "after_hours", "creation_burst", "sensitive_access"}
        self.assertEqual(set(results.keys()), expected_keys)

    def test_all_values_are_dataframes(self):
        records = [_make_record()]
        df = _make_df_from_records(records)
        results = run_all_detections(df)
        for key, val in results.items():
            self.assertIsInstance(val, pd.DataFrame, f"{key} should return DataFrame")


# ─── IP Profiler Tests ────────────────────────────────────────────────────────

class TestIpProfiler(unittest.TestCase):

    def _attacker_df(self) -> pd.DataFrame:
        records = [
            _make_record(event_name="ListBuckets", source_ip=ATTACKER_IP,
                         event_time="2024-03-15T02:14:00Z"),
            _make_record(event_name="GetObject", source_ip=ATTACKER_IP,
                         event_time="2024-03-15T02:15:00Z"),
            _make_record(event_name="AssumeRole", source_ip=ATTACKER_IP,
                         event_source="sts.amazonaws.com",
                         event_time="2024-03-15T02:18:00Z"),
            _make_record(event_name="StopLogging", source_ip=ATTACKER_IP,
                         event_source="cloudtrail.amazonaws.com",
                         event_time="2024-03-15T02:25:00Z"),
        ]
        return _make_df_from_records(records)

    def test_profile_json_structure(self):
        df = self._attacker_df()
        result = profile_ip_json(df, ATTACKER_IP)
        self.assertEqual(result["ip"], ATTACKER_IP)
        self.assertIn("timeline", result)
        self.assertIn("mitre_techniques", result)
        self.assertIn("total_events", result)
        self.assertEqual(result["total_events"], 4)

    def test_mitre_mapping_populated(self):
        df = self._attacker_df()
        result = profile_ip_json(df, ATTACKER_IP)
        # AssumeRole → T1078.004, StopLogging → T1562.008
        self.assertIn("T1078.004", result["mitre_techniques"])
        self.assertIn("T1562.008", result["mitre_techniques"])

    def test_unknown_ip_returns_error(self):
        df = self._attacker_df()
        result = profile_ip_json(df, "1.2.3.4")
        self.assertIn("error", result)

    def test_mitre_map_completeness(self):
        """All keys in MITRE_MAP should map to 3-tuples."""
        for event, mapping in MITRE_MAP.items():
            self.assertEqual(len(mapping), 3, f"MITRE_MAP[{event}] should be (tactic, id, name)")


# ─── Integration Tests ────────────────────────────────────────────────────────

class TestEndToEnd(unittest.TestCase):
    """Integration tests against the sample_data/cloudtrail_logs.json file."""

    @classmethod
    def setUpClass(cls):
        if not Path(SAMPLE_LOG).exists():
            cls.df = None
            return
        from cloudtrail_ingestor import load_from_file, build_dataframe
        records = load_from_file(SAMPLE_LOG)
        cls.df = build_dataframe(records)

    def _skip_if_no_data(self):
        if self.df is None:
            self.skipTest("sample_data/cloudtrail_logs.json not found")

    def test_sample_data_loads(self):
        self._skip_if_no_data()
        self.assertGreater(len(self.df), 0)

    def test_attacker_ip_in_sample_data(self):
        self._skip_if_no_data()
        self.assertIn(ATTACKER_IP, self.df["sourceIPAddress"].values)

    def test_full_detection_suite_on_sample_data(self):
        self._skip_if_no_data()
        results = run_all_detections(self.df)
        # Attacker should appear in at least 3 detection modules
        flagged_modules = sum(
            1 for v in results.values()
            if not v.empty and "sourceIPAddress" in v.columns
            and ATTACKER_IP in v["sourceIPAddress"].values
        )
        self.assertGreaterEqual(flagged_modules, 3,
            f"Attacker should be flagged in ≥3 modules, got {flagged_modules}")

    def test_sensitive_api_detects_stop_logging(self):
        self._skip_if_no_data()
        result = detect_sensitive_api_access(self.df)
        self.assertIn("StopLogging", result["eventName"].values)

    def test_sensitive_api_detects_assume_role(self):
        self._skip_if_no_data()
        result = detect_sensitive_api_access(self.df)
        self.assertIn("AssumeRole", result["eventName"].values)

    def test_attacker_profile_has_mitre_techniques(self):
        self._skip_if_no_data()
        result = profile_ip_json(self.df, ATTACKER_IP)
        self.assertGreater(len(result["mitre_techniques"]), 0)
        self.assertGreaterEqual(result["total_events"], 10)

    def test_creation_burst_detects_cryptomining(self):
        self._skip_if_no_data()
        result = detect_creation_bursts(self.df)
        self.assertFalse(result.empty)
        self.assertIn(ATTACKER_IP, result["sourceIPAddress"].values)


if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=Path(__file__).parent, pattern="test_*.py")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
