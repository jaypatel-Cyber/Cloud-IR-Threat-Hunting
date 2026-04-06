#!/usr/bin/env python3
# Author: Jay Patel
"""
CloudTrail Log Ingestor — reads CloudTrail JSON logs from a local file or
an AWS S3 bucket and flattens nested records into a Pandas DataFrame for
downstream statistical analysis.

Usage:
  python cloudtrail_ingestor.py --input ../sample_data/cloudtrail_logs.json
  python cloudtrail_ingestor.py --input ../sample_data/cloudtrail_logs.json --output /tmp/flat.csv
  python cloudtrail_ingestor.py --s3-bucket my-cloudtrail-bucket --s3-prefix AWSLogs/
  python cloudtrail_ingestor.py --input ../sample_data/cloudtrail_logs.json --json
"""

import argparse
import gzip
import io
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


# ─── Loaders ─────────────────────────────────────────────────────────────────

def load_from_file(path: str) -> List[Dict[str, Any]]:
    """Load CloudTrail records from a local JSON or gzipped JSON file."""
    p = Path(path)
    if not p.exists():
        log.error(f"File not found: {path}")
        sys.exit(1)

    if p.suffix == ".gz":
        with gzip.open(p, "rt") as fh:
            data = json.load(fh)
    else:
        with open(p, "r") as fh:
            data = json.load(fh)

    records = data.get("Records", [])
    log.info(f"Loaded {len(records)} records from {path}")
    return records


def load_from_s3(bucket: str, prefix: str) -> List[Dict[str, Any]]:
    """
    Stream CloudTrail log objects from an S3 bucket (real AWS or LocalStack).
    Expects objects with the .json.gz suffix delivered by CloudTrail.
    Credentials and endpoint are read from environment variables.
    """
    try:
        import boto3
    except ImportError:
        log.error("boto3 required for S3 ingestion: pip install boto3")
        sys.exit(1)

    kwargs: Dict[str, Any] = dict(
        aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
        aws_session_token=os.environ.get("AWS_SESSION_TOKEN"),
        region_name=os.environ.get("AWS_REGION", "us-east-1"),
    )
    endpoint = os.environ.get("AWS_ENDPOINT_URL")
    if endpoint:
        kwargs["endpoint_url"] = endpoint

    s3 = boto3.client("s3", **kwargs)
    paginator = s3.get_paginator("list_objects_v2")
    all_records: List[Dict[str, Any]] = []

    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if not (key.endswith(".json.gz") or key.endswith(".json")):
                continue
            log.info(f"  Fetching s3://{bucket}/{key}")
            response = s3.get_object(Bucket=bucket, Key=key)
            raw = response["Body"].read()

            if key.endswith(".gz"):
                with gzip.open(io.BytesIO(raw), "rt") as fh:
                    data = json.load(fh)
            else:
                data = json.loads(raw)

            all_records.extend(data.get("Records", []))

    log.info(f"Loaded {len(all_records)} records from s3://{bucket}/{prefix}")
    return all_records


# ─── Flattener ───────────────────────────────────────────────────────────────

def _flatten_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Flatten a single nested CloudTrail record into a flat dict.
    Nested fields (userIdentity, requestParameters, responseElements) are
    either extracted as top-level columns or serialized to JSON strings.
    """
    uid = record.get("userIdentity") or {}
    session_issuer = (
        uid.get("sessionContext", {}).get("sessionIssuer", {})
    )
    # Resolve human-readable username across all identity types
    username = (
        uid.get("userName")
        or session_issuer.get("userName")
        or uid.get("principalId", "unknown")
    )

    return {
        "eventTime":          record.get("eventTime"),
        "eventSource":        record.get("eventSource"),
        "eventName":          record.get("eventName"),
        "awsRegion":          record.get("awsRegion"),
        "sourceIPAddress":    record.get("sourceIPAddress"),
        "userAgent":          record.get("userAgent"),
        "errorCode":          record.get("errorCode"),
        "errorMessage":       record.get("errorMessage"),
        "eventID":            record.get("eventID"),
        "eventType":          record.get("eventType"),
        "recipientAccountId": record.get("recipientAccountId"),
        # Identity
        "userType":           uid.get("type"),
        "userArn":            uid.get("arn"),
        "userName":           username,
        "accountId":          uid.get("accountId"),
        "principalId":        uid.get("principalId"),
        # Request/response as JSON strings (flexible downstream parsing)
        "requestParameters":  json.dumps(record.get("requestParameters") or {}),
        "responseElements":   json.dumps(record.get("responseElements") or {}),
    }


def build_dataframe(records: List[Dict[str, Any]]) -> pd.DataFrame:
    """
    Convert a list of raw CloudTrail records into a structured DataFrame.
    Parses eventTime as UTC-aware datetime and sorts chronologically.
    """
    flat = [_flatten_record(r) for r in records]
    df = pd.DataFrame(flat)
    df["eventTime"] = pd.to_datetime(df["eventTime"], utc=True, errors="coerce")
    df.sort_values("eventTime", inplace=True)
    df.reset_index(drop=True, inplace=True)
    log.info(f"DataFrame: {df.shape[0]} rows × {df.shape[1]} columns")
    return df


# ─── CLI ─────────────────────────────────────────────────────────────────────

def _print_summary(df: pd.DataFrame) -> None:
    w = 62
    print(f"\n{'='*w}")
    print(f"  CloudTrail Ingestion Summary")
    print(f"{'='*w}")
    print(f"  Total events  : {len(df):,}")
    print(f"  Time range    : {df['eventTime'].min()}  ->")
    print(f"                  {df['eventTime'].max()}")
    print(f"  Unique IPs    : {df['sourceIPAddress'].nunique()}")
    print(f"  Unique users  : {df['userName'].nunique()}")
    print(f"  Event sources : {', '.join(df['eventSource'].dropna().unique())}")
    print(f"  Error events  : {df['errorCode'].notna().sum()}")
    print(f"{'='*w}\n")
    print(df[["eventTime", "userName", "sourceIPAddress", "eventName", "errorCode"]]
          .to_string(index=False))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Ingest AWS CloudTrail logs into a Pandas DataFrame"
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--input", metavar="FILE",
                        help="Path to local CloudTrail JSON (or .json.gz) file")
    source.add_argument("--s3-bucket", metavar="BUCKET",
                        help="S3 bucket containing CloudTrail log objects")

    parser.add_argument("--s3-prefix", metavar="PREFIX", default="",
                        help="S3 key prefix / folder path (default: '')")
    parser.add_argument("--output", metavar="FILE",
                        help="Save flattened DataFrame to this CSV path")
    parser.add_argument("--json", action="store_true", dest="json_out",
                        help="Print flattened records as JSON instead of table")
    args = parser.parse_args()

    if args.input:
        records = load_from_file(args.input)
    else:
        records = load_from_s3(args.s3_bucket, args.s3_prefix)

    df = build_dataframe(records)

    if args.output:
        df.to_csv(args.output, index=False)
        print(f"✓ Saved {len(df):,} records to {args.output}")
    elif args.json_out:
        print(df.to_json(orient="records", date_format="iso", indent=2))
    else:
        _print_summary(df)


if __name__ == "__main__":
    main()
