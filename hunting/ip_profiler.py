#!/usr/bin/env python3
# Author: Jay Patel
"""
IP Profiler — given a suspect IP address, builds a complete chronological
action timeline from CloudTrail logs and maps every observed API call to
its MITRE ATT&CK for Cloud technique.

Usage:
  python ip_profiler.py --input /tmp/flat.csv --ip 185.220.101.47
  python ip_profiler.py --input /tmp/flat.csv --ip 185.220.101.47 --json
"""

import argparse
import json
import logging
import sys
from typing import Dict, Tuple

import pandas as pd

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

# ─── MITRE ATT&CK for Cloud mapping ──────────────────────────────────────────
# eventName → (tactic, technique_id, technique_name)
MITRE_MAP: Dict[str, Tuple[str, str, str]] = {
    # Discovery — T1580 Cloud Infrastructure Discovery
    "ListBuckets":           ("Discovery",            "T1580",     "Cloud Infrastructure Discovery"),
    "ListObjects":           ("Discovery",            "T1580",     "Cloud Infrastructure Discovery"),
    "GetBucketAcl":          ("Discovery",            "T1580",     "Cloud Infrastructure Discovery"),
    "GetBucketPolicy":       ("Discovery",            "T1580",     "Cloud Infrastructure Discovery"),
    "DescribeInstances":     ("Discovery",            "T1580",     "Cloud Infrastructure Discovery"),
    "DescribeSecurityGroups":("Discovery",            "T1580",     "Cloud Infrastructure Discovery"),
    "DescribeVpcs":          ("Discovery",            "T1580",     "Cloud Infrastructure Discovery"),
    # Discovery — T1087.004 Account Discovery: Cloud Account
    "ListUsers":             ("Discovery",            "T1087.004", "Account Discovery: Cloud Account"),
    "ListRoles":             ("Discovery",            "T1087.004", "Account Discovery: Cloud Account"),
    "GetUser":               ("Discovery",            "T1087.004", "Account Discovery: Cloud Account"),
    "ListAccessKeys":        ("Discovery",            "T1087.004", "Account Discovery: Cloud Account"),
    # Collection — T1530 Data from Cloud Storage Object
    "GetObject":             ("Collection",           "T1530",     "Data from Cloud Storage Object"),
    # Collection — T1552 Unsecured Credentials
    "GetSecretValue":        ("Collection",           "T1552.004", "Unsecured Credentials: Cloud Instance Metadata"),
    "GetPasswordData":       ("Collection",           "T1552.004", "Unsecured Credentials"),
    # Privilege Escalation / Lateral Movement
    "AssumeRole":            ("Privilege Escalation", "T1078.004", "Valid Accounts: Cloud Accounts"),
    "AttachRolePolicy":      ("Privilege Escalation", "T1078.004", "Valid Accounts: Cloud Accounts"),
    "PutUserPolicy":         ("Privilege Escalation", "T1098",     "Account Manipulation"),
    "UpdateAssumeRolePolicy":("Privilege Escalation", "T1078.004", "Valid Accounts: Cloud Accounts"),
    # Persistence
    "CreateAccessKey":       ("Persistence",          "T1098.001", "Account Manipulation: Additional Cloud Credentials"),
    "CreateLoginProfile":    ("Persistence",          "T1098",     "Account Manipulation"),
    "UpdateAccessKey":       ("Persistence",          "T1098.001", "Account Manipulation: Additional Cloud Credentials"),
    # Initial Access
    "ConsoleLogin":          ("Initial Access",       "T1078.004", "Valid Accounts: Cloud Accounts"),
    # Impact — T1496 Resource Hijacking (cryptomining)
    "RunInstances":          ("Impact",               "T1496",     "Resource Hijacking"),
    "CreateSecurityGroup":   ("Impact",               "T1496",     "Resource Hijacking"),
    # Defense Evasion — T1562.008 Disable Cloud Logs
    "StopLogging":           ("Defense Evasion",      "T1562.008", "Disable Cloud Logs"),
    "DeleteTrail":           ("Defense Evasion",      "T1562.008", "Disable Cloud Logs"),
    # Defense Evasion — T1222 / T1070
    "PutBucketPolicy":       ("Defense Evasion",      "T1222",     "File and Directory Permissions Modification"),
    "DeleteBucketPolicy":    ("Defense Evasion",      "T1070",     "Indicator Removal"),
}

# Severity priority for sorting (higher = more severe)
TACTIC_SEVERITY = {
    "Defense Evasion":      6,
    "Impact":               5,
    "Persistence":          4,
    "Privilege Escalation": 4,
    "Collection":           3,
    "Initial Access":       2,
    "Discovery":            1,
}


def profile_ip(df: pd.DataFrame, ip: str) -> None:
    """Print a full threat investigation profile for a given source IP."""
    ip_df = df[df["sourceIPAddress"] == ip].copy()

    if ip_df.empty:
        print(f"✗ No events found for IP: {ip}")
        sys.exit(0)

    ip_df.sort_values("eventTime", inplace=True)
    w = 67

    print(f"\n{'='*w}")
    print(f"  THREAT PROFILE - {ip}")
    print(f"{'='*w}")
    print(f"  First seen   : {ip_df['eventTime'].min()}")
    print(f"  Last seen    : {ip_df['eventTime'].max()}")
    duration = ip_df['eventTime'].max() - ip_df['eventTime'].min()
    print(f"  Duration     : {duration}")
    print(f"  Total events : {len(ip_df):,}")
    print(f"  Unique users : {ip_df['userName'].nunique()} -> {list(ip_df['userName'].unique())}")
    print(f"  Regions hit  : {sorted(ip_df['awsRegion'].dropna().unique().tolist())}")
    print(f"  Error count  : {ip_df['errorCode'].notna().sum()} / {len(ip_df)} ({ip_df['errorCode'].notna().mean()*100:.0f}%)")
    uas = ip_df['userAgent'].dropna().unique()[:3].tolist()
    print(f"  User agents  : {uas}")

    # MITRE ATT&CK mapping
    sep = "-" * (w - 29)
    print(f"\n  -- MITRE ATT&CK for Cloud --{sep}")
    seen: set = set()
    mitre_hits = []
    for _, row in ip_df.iterrows():
        event = row["eventName"]
        if event in MITRE_MAP:
            tactic, tid, tname = MITRE_MAP[event]
            key = (tid, event)
            if key not in seen:
                seen.add(key)
                severity = TACTIC_SEVERITY.get(tactic, 0)
                mitre_hits.append((severity, tactic, tid, tname, event))

    if mitre_hits:
        for _, tactic, tid, tname, event in sorted(mitre_hits, key=lambda x: -x[0]):
            print(f"  [{tactic:<22}] {tid:<12} {tname} (via {event})")
    else:
        print("  No direct MITRE ATT&CK mappings found.")

    # Phase summary
    sep2 = "-" * (w - 27)
    print(f"\n  -- Attack Phase Summary --{sep2}")
    phase_map = {
        "Discovery":            [],
        "Collection":           [],
        "Privilege Escalation": [],
        "Persistence":          [],
        "Impact":               [],
        "Defense Evasion":      [],
    }
    for _, row in ip_df.iterrows():
        if row["eventName"] in MITRE_MAP:
            tactic = MITRE_MAP[row["eventName"]][0]
            if tactic in phase_map:
                phase_map[tactic].append(row["eventName"])

    for phase, events in phase_map.items():
        if events:
            uniq = list(dict.fromkeys(events))  # deduplicate preserving order
            print(f"  {phase:<22}: {', '.join(uniq)}")

    # Full chronological timeline
    print(f"\n  -- Full Action Timeline --{sep2}")
    for _, row in ip_df.iterrows():
        if pd.notna(row["errorCode"]):
            status = f"ERR:{row['errorCode']}"
        else:
            status = "OK"
        region = row.get("awsRegion", "?")
        print(f"  {str(row['eventTime']):<32}  [{status:>20}]  {row['eventName']:<28} ({region})")

    # Event source breakdown
    print(f"\n  -- API Calls by Service --{sep2}")
    for src, grp in ip_df.groupby("eventSource"):
        calls = " | ".join(grp["eventName"].unique())
        print(f"  {src:<36}: {calls}")

    print(f"{'='*w}\n")


def profile_ip_json(df: pd.DataFrame, ip: str) -> dict:
    """Return a structured dict representation of the IP profile."""
    ip_df = df[df["sourceIPAddress"] == ip].copy().sort_values("eventTime")
    if ip_df.empty:
        return {"error": f"No events for IP {ip}"}

    mitre = {}
    for _, row in ip_df.iterrows():
        event = row["eventName"]
        if event in MITRE_MAP:
            tactic, tid, tname = MITRE_MAP[event]
            if tid not in mitre:
                mitre[tid] = {"tactic": tactic, "technique": tname, "events": []}
            if event not in mitre[tid]["events"]:
                mitre[tid]["events"].append(event)

    return {
        "ip": ip,
        "first_seen": str(ip_df["eventTime"].min()),
        "last_seen": str(ip_df["eventTime"].max()),
        "total_events": len(ip_df),
        "unique_users": ip_df["userName"].unique().tolist(),
        "regions": sorted(ip_df["awsRegion"].dropna().unique().tolist()),
        "error_rate": round(ip_df["errorCode"].notna().mean(), 3),
        "mitre_techniques": mitre,
        "timeline": json.loads(
            ip_df[["eventTime", "userName", "eventName", "awsRegion", "errorCode"]]
            .to_json(orient="records", date_format="iso")
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build a threat profile for a suspect IP from CloudTrail logs"
    )
    parser.add_argument("--input", required=True, metavar="CSV",
                        help="Flattened CloudTrail CSV from cloudtrail_ingestor.py")
    parser.add_argument("--ip", required=True, metavar="IP",
                        help="Suspect IP address to profile")
    parser.add_argument("--json", action="store_true", dest="json_out",
                        help="Output as structured JSON instead of human-readable profile")
    args = parser.parse_args()

    df = pd.read_csv(args.input, parse_dates=["eventTime"])

    if args.json_out:
        result = profile_ip_json(df, args.ip)
        print(json.dumps(result, indent=2, default=str))
    else:
        profile_ip(df, args.ip)


if __name__ == "__main__":
    main()
