#!/usr/bin/env python3
# Author: Jay Patel
"""
CloudTrail Anomaly Detector — six statistical detection modules that hunt
for suspicious API activity patterns in a flattened CloudTrail DataFrame.

Detection modules:
  api_frequency   — Z-score: IPs with abnormally high API call volume
  error_rate      — IQR fence: IPs with outlier AccessDenied error rates
  rare_api_calls  — Frequency: calls that appear < RARE_API_THRESHOLD of all events
  after_hours     — Time-of-day: non-service API calls between 00:00–07:00 UTC
  creation_burst  — Count: IPs/users triggering ≥ N resource-creation calls
  sensitive_access — Allowlist: calls to high-risk APIs (AssumeRole, GetSecretValue…)

Usage:
  python anomaly_detector.py --input /tmp/flat.csv
  python anomaly_detector.py --input /tmp/flat.csv --module error_rate
  python anomaly_detector.py --input /tmp/flat.csv --json
"""

import argparse
import json
import logging
import sys
from typing import Dict

import numpy as np
import pandas as pd

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

# ─── Tunable thresholds ───────────────────────────────────────────────────────
ZSCORE_THRESHOLD = 2.5      # Flag IPs whose call volume z-score exceeds this
IQR_MULTIPLIER = 1.5        # Upper fence = Q3 + IQR_MULTIPLIER × IQR
RARE_API_THRESHOLD = 0.02   # Events making up < 2% of total = rare
AFTER_HOURS_START = 0       # Suspicious window start hour (UTC, inclusive)
AFTER_HOURS_END = 7         # Suspicious window end hour (UTC, exclusive)
CREATION_BURST_THRESHOLD = 3  # ≥ N resource-creation calls = burst alert

# High-signal resource-creation events
CREATION_EVENTS = frozenset({
    "RunInstances", "CreateUser", "CreateAccessKey",
    "CreateRole", "CreateBucket", "AttachRolePolicy",
    "PutUserPolicy", "CreateLoginProfile", "CreateVpc",
})

# High-risk events that warrant investigation regardless of frequency
SENSITIVE_EVENTS = frozenset({
    "AssumeRole", "GetSecretValue", "GetPasswordData",
    "UpdateAccessKey", "CreateAccessKey", "DeleteTrail",
    "StopLogging", "PutBucketPolicy", "DeleteBucketPolicy",
    "AttachRolePolicy", "PutUserPolicy", "UpdateAssumeRolePolicy",
})


# ─── Detection modules ────────────────────────────────────────────────────────

def detect_api_frequency_anomalies(df: pd.DataFrame) -> pd.DataFrame:
    """
    Z-score based detection on per-IP API call volume.

    An attacker conducting automated recon or exfil will issue many more
    API calls than a typical human user. This flags IPs with call counts
    more than ZSCORE_THRESHOLD standard deviations above the mean.

    Returns: DataFrame with columns [sourceIPAddress, call_count, z_score]
    """
    counts = df.groupby("sourceIPAddress").size().reset_index(name="call_count")
    if len(counts) < 3:
        log.warning("api_frequency: too few IPs for meaningful z-score, skipping")
        return counts.iloc[0:0]

    mu = counts["call_count"].mean()
    sigma = counts["call_count"].std(ddof=1)
    if sigma == 0:
        return counts.iloc[0:0]

    counts["z_score"] = (counts["call_count"] - mu) / sigma
    counts["mean_calls"] = round(mu, 2)
    anomalies = counts[counts["z_score"] >= ZSCORE_THRESHOLD].copy()
    anomalies.sort_values("z_score", ascending=False, inplace=True)
    return anomalies.reset_index(drop=True)


def detect_error_rate_anomalies(df: pd.DataFrame) -> pd.DataFrame:
    """
    IQR-based detection on per-IP AccessDenied error rates.

    High error rates from a single IP indicate credential stuffing, bucket
    enumeration, or privilege probing. IQR is more robust to outliers than
    mean/stdev for this metric.

    Returns: DataFrame with [sourceIPAddress, total, error_count, error_rate]
    """
    total = df.groupby("sourceIPAddress").size().reset_index(name="total")
    errors = (
        df[df["errorCode"].notna()]
        .groupby("sourceIPAddress")
        .size()
        .reset_index(name="error_count")
    )
    merged = total.merge(errors, on="sourceIPAddress", how="left").fillna(0)
    merged["error_rate"] = merged["error_count"] / merged["total"]

    q1 = merged["error_rate"].quantile(0.25)
    q3 = merged["error_rate"].quantile(0.75)
    iqr = q3 - q1
    fence = q3 + IQR_MULTIPLIER * iqr

    anomalies = merged[merged["error_rate"] > fence].copy()
    anomalies.sort_values("error_rate", ascending=False, inplace=True)
    return anomalies.reset_index(drop=True)


def detect_rare_api_calls(df: pd.DataFrame) -> pd.DataFrame:
    """
    Frequency-based detection for low-occurrence API calls.

    Certain API calls (StopLogging, DeleteTrail, GetPasswordData) are almost
    never called in normal operations. Any occurrence is high-signal and
    warrants investigation regardless of source IP.

    Returns: DataFrame with [eventName, sourceIPAddress, count, frequency]
    """
    freq = (
        df["eventName"]
        .value_counts(normalize=True)
        .reset_index()
    )
    freq.columns = ["eventName", "frequency"]
    rare_names = freq[freq["frequency"] < RARE_API_THRESHOLD]["eventName"]

    rare_events = df[df["eventName"].isin(rare_names)]
    if rare_events.empty:
        return rare_events[["eventName", "sourceIPAddress"]].iloc[0:0]

    summary = (
        rare_events
        .groupby(["eventName", "sourceIPAddress"])
        .size()
        .reset_index(name="count")
    )
    summary = summary.merge(freq, on="eventName")
    summary.sort_values("frequency", inplace=True)
    return summary.reset_index(drop=True)


def detect_after_hours_activity(df: pd.DataFrame) -> pd.DataFrame:
    """
    Time-of-day based detection for off-hours API activity.

    Compromised credentials are frequently used outside business hours by
    attackers in different timezones. Non-service-account calls between
    AFTER_HOURS_START and AFTER_HOURS_END UTC are flagged.

    Returns: DataFrame of suspicious events with timing context.
    """
    work_df = df.copy()
    work_df["hour"] = work_df["eventTime"].dt.hour
    mask = (
        (work_df["hour"] >= AFTER_HOURS_START) &
        (work_df["hour"] < AFTER_HOURS_END) &
        (~work_df["userType"].isin(["AWSService", "AWSAccount"]))
    )
    after_hours = work_df[mask].copy()
    cols = ["eventTime", "userName", "sourceIPAddress", "eventName", "awsRegion", "errorCode", "hour"]
    return after_hours[cols].reset_index(drop=True)


def detect_creation_bursts(df: pd.DataFrame) -> pd.DataFrame:
    """
    Count-based detection for resource-creation API bursts.

    An attacker setting up cryptomining infrastructure or establishing
    persistence will trigger multiple RunInstances, CreateAccessKey, or
    AttachRolePolicy calls in quick succession. Flag any IP/user pair
    that calls ≥ CREATION_BURST_THRESHOLD resource-creation APIs.

    Returns: DataFrame with [sourceIPAddress, userName, creation_count, events, timespan_seconds]
    """
    creation_df = df[df["eventName"].isin(CREATION_EVENTS)].copy()
    if creation_df.empty:
        return creation_df[["sourceIPAddress", "userName"]].iloc[0:0]

    def _agg(g: pd.DataFrame) -> pd.Series:
        span = (g["eventTime"].max() - g["eventTime"].min()).total_seconds()
        return pd.Series({
            "creation_count": len(g),
            "events": ", ".join(g["eventName"].tolist()),
            "first_seen": g["eventTime"].min(),
            "last_seen": g["eventTime"].max(),
            "timespan_seconds": span,
        })

    burst = (
        creation_df
        .groupby(["sourceIPAddress", "userName"])
        .apply(_agg)
        .reset_index()
    )
    burst = burst[burst["creation_count"] >= CREATION_BURST_THRESHOLD]
    burst.sort_values("creation_count", ascending=False, inplace=True)
    return burst.reset_index(drop=True)


def detect_sensitive_api_access(df: pd.DataFrame) -> pd.DataFrame:
    """
    Allowlist-based detection for calls to high-risk APIs.

    These API calls (AssumeRole, StopLogging, GetSecretValue, etc.) are
    almost always worth reviewing regardless of frequency or timing.

    Returns: DataFrame of all sensitive API call events.
    """
    sensitive = df[df["eventName"].isin(SENSITIVE_EVENTS)].copy()
    cols = ["eventTime", "userName", "sourceIPAddress", "eventName", "awsRegion", "errorCode"]
    return sensitive[cols].reset_index(drop=True)


# ─── Orchestrator ─────────────────────────────────────────────────────────────

def run_all_detections(df: pd.DataFrame) -> Dict[str, pd.DataFrame]:
    """Run all six detection modules and return a named dict of findings."""
    log.info("Running CloudTrail anomaly detection suite (6 modules)...")

    results = {
        "api_frequency":   detect_api_frequency_anomalies(df),
        "error_rate":      detect_error_rate_anomalies(df),
        "rare_api_calls":  detect_rare_api_calls(df),
        "after_hours":     detect_after_hours_activity(df),
        "creation_burst":  detect_creation_bursts(df),
        "sensitive_access": detect_sensitive_api_access(df),
    }

    for name, result_df in results.items():
        flag = "[!!]" if not result_df.empty else "[ OK]"
        log.info(f"  {flag} {name:<22} {len(result_df)} finding(s)")

    return results


# ─── CLI ─────────────────────────────────────────────────────────────────────

def _print_results(results: Dict[str, pd.DataFrame]) -> None:
    w = 62
    for name, result_df in results.items():
        print(f"\n{'='*w}")
        flag = "[!!]" if not result_df.empty else "[ OK]"
        print(f"  {flag} {name.upper().replace('_', ' ')} - {len(result_df)} finding(s)")
        print(f"{'='*w}")
        if result_df.empty:
            print("  No anomalies detected.")
        else:
            print(result_df.to_string(index=False))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Statistical anomaly detection on flattened CloudTrail logs"
    )
    parser.add_argument("--input", required=True, metavar="CSV",
                        help="Flattened CloudTrail CSV produced by cloudtrail_ingestor.py")
    parser.add_argument(
        "--module",
        choices=["api_frequency", "error_rate", "rare_api_calls",
                 "after_hours", "creation_burst", "sensitive_access", "all"],
        default="all",
        help="Which detection module to run (default: all)",
    )
    parser.add_argument("--json", action="store_true", dest="json_out",
                        help="Output findings as JSON")
    args = parser.parse_args()

    df = pd.read_csv(args.input, parse_dates=["eventTime"])

    all_results = run_all_detections(df)
    if args.module == "all":
        results = all_results
    else:
        results = {args.module: all_results[args.module]}

    if args.json_out:
        out = {
            k: json.loads(v.to_json(orient="records", date_format="iso"))
            for k, v in results.items()
        }
        print(json.dumps(out, indent=2, default=str))
    else:
        _print_results(results)


if __name__ == "__main__":
    main()
