# Project 4: Cloud Incident Response & Threat Hunting (AWS)

| Field      | Detail                                      |
|------------|---------------------------------------------|
| Role Focus | Cloud SOC Analyst / Cloud IR Specialist     |
| Difficulty | ★★★★☆ Advanced                              |
| Status     | Complete                                    |
| Stack      | Python 3, Pandas, AWS CloudTrail, LocalStack, Jupyter, Sigma |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│               Deliberately Vulnerable AWS Environment                │
│   S3 (misconfigured) · IAM (over-privileged) · EC2 (open SG)        │
└─────────────────────────────────────────┬───────────────────────────┘
                                          │ CloudTrail API Logging
                    ┌─────────────────────┼─────────────────────┐
                    │                     │                     │
             ┌──────▼──────┐      ┌───────▼──────┐    ┌────────▼───────┐
             │  Local JSON  │      │   AWS S3     │    │ CloudWatch Logs│
             │  (Dev/Lab)   │      │   Bucket     │    │  (Production)  │
             └──────┬──────┘      └───────┬──────┘    └────────┬───────┘
                    └─────────────────────┼─────────────────────┘
                                          │
                              ┌───────────▼───────────┐
                              │  cloudtrail_ingestor   │
                              │  Records → DataFrame   │
                              └───────────┬───────────┘
                                          │
                         ┌────────────────▼────────────────┐
                         │        anomaly_detector          │
                         │  ┌──────────────────────────┐   │
                         │  │ Z-Score  API Frequency   │   │
                         │  │ IQR      Error Rate Spike│   │
                         │  │ Baseline Rare API Calls  │   │
                         │  │ Clock    After-Hours Hunt │   │
                         │  │ Burst    Resource Creation│   │
                         │  │ Triage   Sensitive APIs  │   │
                         │  └──────────────────────────┘   │
                         └────────────────┬────────────────┘
                                          │
                         ┌────────────────▼────────────────┐
                         │          ip_profiler             │
                         │  Timeline + MITRE ATT&CK Map     │
                         │  T1530 · T1078.004 · T1496       │
                         └────────────────┬────────────────┘
                                          │
                         ┌────────────────▼────────────────┐
                         │      hunt_orchestrator           │
                         │   JSON Investigation Report      │
                         └─────────────────────────────────┘
```

---

## Stack

| Component             | Tool                     | Role                                        |
|-----------------------|--------------------------|---------------------------------------------|
| Cloud Simulation      | LocalStack 3.4           | Local AWS (S3, IAM, EC2, CloudTrail, STS)   |
| Log Ingestion         | cloudtrail_ingestor.py   | Parses CloudTrail JSON → Pandas DataFrame   |
| Statistical Analysis  | Pandas + NumPy           | Z-score, IQR, frequency anomaly detection   |
| IP Profiling          | ip_profiler.py           | Builds attacker timeline + MITRE mapping    |
| Hunt Orchestration    | hunt_orchestrator.py     | End-to-end pipeline, JSON report output     |
| Interactive Analysis  | Jupyter Lab              | Step-by-step notebook with visualizations   |
| Detection Rules       | Sigma (YAML)             | CloudTrail-native Sigma rules               |
| Cloud Simulation API  | boto3                    | S3/IAM/EC2 API calls (LocalStack endpoint)  |
| Attack Simulation     | generate_attack_logs.py  | Synthetic CloudTrail log generation         |

---

## Attack Scenarios Simulated

### 1. S3 Bucket Misconfiguration + Data Exfiltration
- Attacker enumerates buckets via `ListBuckets`, `GetBucketAcl`
- Discovers publicly accessible bucket (`company-public-assets`)
- Exfiltrates HR exports, salary data, DB credentials via `GetObject`
- **MITRE:** T1530 — Data from Cloud Storage Object

### 2. IAM Role Hijacking + Persistence
- Uses stolen dev credentials to enumerate `ListUsers`, `ListRoles`
- `AssumeRole` on `ec2-admin-role` for lateral movement
- Creates new `AccessKey` for persistent backdoor access
- **MITRE:** T1078.004 — Valid Accounts: Cloud Accounts | T1098.001 — Additional Cloud Credentials

### 3. Cryptomining EC2 Deployment
- Launches `p3.16xlarge` GPU instance in non-standard region (`ap-southeast-1`)
- Creates permissive Security Group (SSH 0.0.0.0/0)
- **MITRE:** T1496 — Resource Hijacking

### 4. Defense Evasion
- `StopLogging` + `DeleteTrail` attempt to blind the SOC
- **MITRE:** T1562.008 — Disable Cloud Logs

---

## Setup

### Option A — Local File (No AWS Required)

```bash
# 1. Clone and install dependencies
cd Project_4_Cloud_IR_Threat_Hunting
pip install -r requirements.txt

# 2. Run the full hunt pipeline against sample data
cd hunting
python hunt_orchestrator.py --input ../sample_data/cloudtrail_logs.json --profile-suspects

# 3. Open the interactive Jupyter notebook
jupyter lab ../notebooks/cloud_threat_hunt.ipynb
```

### Option B — LocalStack (Full AWS Simulation)

```bash
# 1. Start LocalStack + Jupyter
docker-compose up -d

# 2. Generate and upload simulated attack logs
cd attack_simulation
python generate_attack_logs.py --output ../sample_data/cloudtrail_logs.json --upload-localstack

# 3. Run orchestrator against LocalStack S3
cd ../hunting
AWS_ENDPOINT_URL=http://localhost:4566 \
python hunt_orchestrator.py --s3-bucket cloudtrail-logs --s3-prefix AWSLogs/ --profile-suspects
```

### Option C — Real AWS CloudTrail

```bash
# 1. Set real credentials
cp ../.env.example ../.env
# Edit .env with real AWS keys

# 2. Enable CloudTrail in your AWS account → deliver to S3 bucket
# 3. Run against real logs
python hunt_orchestrator.py --s3-bucket YOUR-CLOUDTRAIL-BUCKET --s3-prefix AWSLogs/ --profile-suspects
```

---

## Running Individual Modules

```bash
# Ingest only
python hunting/cloudtrail_ingestor.py --input sample_data/cloudtrail_logs.json --output /tmp/flat.csv

# Detect anomalies (all modules)
python hunting/anomaly_detector.py --input /tmp/flat.csv

# Run one specific module
python hunting/anomaly_detector.py --input /tmp/flat.csv --module error_rate

# Profile a specific suspect IP
python hunting/ip_profiler.py --input /tmp/flat.csv --ip 185.220.101.47

# Full hunt + JSON output
python hunting/hunt_orchestrator.py --input sample_data/cloudtrail_logs.json --json
```

---

## MITRE ATT&CK Coverage

| Tactic               | Technique ID | Technique Name                          | Detection Module         |
|----------------------|--------------|-----------------------------------------|--------------------------|
| Discovery            | T1580        | Cloud Infrastructure Discovery          | rare_api_calls           |
| Discovery            | T1087.004    | Account Discovery: Cloud Account        | sensitive_access         |
| Collection           | T1530        | Data from Cloud Storage Object          | sensitive_access         |
| Privilege Escalation | T1078.004    | Valid Accounts: Cloud Accounts          | sensitive_access         |
| Persistence          | T1098.001    | Additional Cloud Credentials            | creation_burst           |
| Impact               | T1496        | Resource Hijacking (Cryptomining)       | creation_burst           |
| Defense Evasion      | T1562.008    | Disable Cloud Logs                      | rare_api_calls           |

---

## Detection Logic Summary

| Module               | Method         | Signal                                          | Threshold              |
|----------------------|----------------|-------------------------------------------------|------------------------|
| api_frequency        | Z-Score        | IP making statistically abnormal call volume    | z ≥ 2.5                |
| error_rate           | IQR Fence      | IP with outlier AccessDenied rate (recon)       | Q3 + 1.5×IQR           |
| rare_api_calls       | Frequency      | Low-frequency calls (StopLogging, DeleteTrail)  | < 2% of all events     |
| after_hours          | Time-of-day    | Non-service account activity 00:00–07:00 UTC    | Hour in [0,7)           |
| creation_burst       | Count          | ≥ 3 resource-creation calls (RunInstances, etc) | count ≥ 3              |
| sensitive_access     | Allowlist      | Calls to high-risk APIs regardless of frequency | Hard-coded set         |

---

## Skills Demonstrated

| Skill                          | Evidence                                              |
|--------------------------------|-------------------------------------------------------|
| AWS CloudTrail Log Analysis    | Parsing nested CloudTrail JSON, field flattening      |
| Statistical Threat Hunting     | Z-score + IQR anomaly detection on API call patterns  |
| Data Science for Security      | Pandas DataFrame pipeline, time-series analysis       |
| Cloud Attack Simulation        | Synthetic attack log generation covering 4 scenarios  |
| MITRE ATT&CK for Cloud         | 7 technique mappings across 4 tactics                 |
| Sigma Rule Authoring           | 3 CloudTrail-native Sigma detection rules             |
| Python Security Tooling        | 4 modular CLI scripts with argparse + logging         |
| Jupyter Notebook Reporting     | Interactive investigation notebook with visualizations|
| AWS IAM & S3 Security          | Understanding of misconfiguration attack paths        |
| IR Report Generation           | Automated JSON investigation report with timeline     |
