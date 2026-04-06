# Architecture — Cloud IR & Threat Hunting (AWS)

## Data Flow

```
ATTACK SIMULATION
─────────────────
generate_attack_logs.py
  │  Crafts synthetic CloudTrail Records
  │  covering 4 attack scenarios
  └──► sample_data/cloudtrail_logs.json
       OR uploads to LocalStack S3

INGESTION
─────────
cloudtrail_ingestor.py
  ├── Source: Local JSON file
  ├── Source: AWS S3 (real or LocalStack)
  └── Output: pandas DataFrame
       Columns: eventTime, eventName, eventSource,
                sourceIPAddress, userName, userType,
                awsRegion, errorCode, requestParameters

DETECTION ENGINE (anomaly_detector.py)
───────────────────────────────────────
┌──────────────────────────────────────────────────────────┐
│  Module             │ Method    │ Target                  │
│─────────────────────│───────────│─────────────────────────│
│  api_frequency      │ Z-Score   │ Calls per IP (volume)   │
│  error_rate         │ IQR Fence │ AccessDenied rate/IP    │
│  rare_api_calls     │ Frequency │ StopLogging, DeleteTrail│
│  after_hours        │ Time mask │ Non-SVC calls 00–07 UTC │
│  creation_burst     │ Count     │ RunInstances + 2 others  │
│  sensitive_access   │ Allowlist │ AssumeRole, GetSecret... │
└──────────────────────────────────────────────────────────┘

IP PROFILING (ip_profiler.py)
──────────────────────────────
For each suspect IP:
  ├── Full chronological event timeline
  ├── MITRE ATT&CK for Cloud technique mapping
  ├── Unique regions + user agents
  └── Grouped by event source (s3, iam, ec2...)

ORCHESTRATION (hunt_orchestrator.py)
──────────────────────────────────────
  Ingest → Detect → Triage → Report
  Output: reports/hunt_YYYYMMDD_HHMMSS.json

INTERACTIVE ANALYSIS (Jupyter Notebook)
─────────────────────────────────────────
  notebooks/cloud_threat_hunt.ipynb
  ├── Cell 1: Load + explore CloudTrail logs
  ├── Cell 2: Time-series API call heatmap
  ├── Cell 3: Z-Score frequency analysis (scatter)
  ├── Cell 4: Error rate IQR boxplot
  ├── Cell 5: Attacker IP isolation + timeline
  └── Cell 6: MITRE ATT&CK matrix visualization
```

## Component Table

| Component                | File                              | Purpose                                    |
|--------------------------|-----------------------------------|--------------------------------------------|
| Log Ingestor             | hunting/cloudtrail_ingestor.py    | JSON/S3 → DataFrame                        |
| Anomaly Detector         | hunting/anomaly_detector.py       | 6 statistical detection modules             |
| IP Profiler              | hunting/ip_profiler.py            | Timeline + MITRE mapping per suspect IP     |
| Hunt Orchestrator        | hunting/hunt_orchestrator.py      | End-to-end pipeline + JSON report           |
| Attack Simulator         | attack_simulation/generate_attack_logs.py | Synthetic CloudTrail generation  |
| Jupyter Notebook         | notebooks/cloud_threat_hunt.ipynb | Interactive data science analysis           |
| Sigma Rule — S3          | sigma_rules/s3_unauthorized_access.yml    | Bucket enumeration detection       |
| Sigma Rule — IAM         | sigma_rules/iam_role_hijacking.yml        | AssumeRole + key creation detection|
| Sigma Rule — Crypto      | sigma_rules/cryptomining_ec2.yml          | Large GPU instance launch detection|
| Sample Logs              | sample_data/cloudtrail_logs.json  | 65 synthetic CloudTrail records             |

## Attack Scenario Timeline

```
2024-03-15 02:14:00 UTC  [ATTACKER: 185.220.101.47]
  ├── 02:14:00  ListBuckets        → AccessDenied     (T1580  Discovery)
  ├── 02:14:12  GetBucketAcl x3   → AccessDenied x2  (T1580  Discovery)
  ├── 02:14:35  GetBucketAcl      → OK   ← public bucket found!
  ├── 02:14:47  ListObjects        → OK                (T1580  Discovery)
  ├── 02:15:01  GetObject          → OK   ← HR data exfil (T1530 Collection)
  ├── 02:15:14  GetObject          → OK   ← salary data
  ├── 02:15:28  GetObject          → OK   ← DB credentials
  ├── 02:16:00  ListBuckets        → OK   (stolen dev creds)
  ├── 02:16:15  GetObject          → OK   ← finance data (T1530)
  ├── 02:17:00  ListUsers          → OK                (T1087.004 Discovery)
  ├── 02:17:15  ListRoles          → OK
  ├── 02:18:00  AssumeRole         → OK   ← lateral movement (T1078.004)
  ├── 02:18:30  CreateAccessKey    → OK   ← persistence backdoor (T1098.001)
  ├── 02:20:00  RunInstances p3.16xlarge ap-southeast-1 ← cryptomining (T1496)
  ├── 02:21:00  CreateSecurityGroup → OK  (open SSH 0.0.0.0/0)
  ├── 02:22:00  PutBucketPolicy    → OK   (makes bucket public again)
  ├── 02:25:00  StopLogging        → OK   ← cover tracks (T1562.008)
  └── 02:28:00  DeleteTrail        → AccessDenied (insufficient perms)

2024-03-15 09:00–17:00 UTC  [NORMAL USERS: 72.21.198.x]
  └── alice.johnson, bob.smith, david.chen, svc-ci-deploy
      Normal S3 / EC2 / IAM / CloudWatch API usage
```
