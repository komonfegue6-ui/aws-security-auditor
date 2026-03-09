# AWS Security Auditor 🔒

An automated AWS security auditing tool that scans your AWS account for 
misconfigurations and security risks across S3, IAM, and EC2.

## Architecture
```
EventBridge (Weekly Trigger)
        ↓
AWS Lambda (Python 3.12)
        ↓
┌───────────────────────────┐
│  S3 Bucket Scanner        │
│  IAM User Scanner         │
│  EC2 Security Group Scanner│
└───────────────────────────┘
        ↓
CloudWatch Logs (Results)
```

## What It Checks

**S3 Buckets**
- Detects publicly accessible buckets
- Flags buckets open to AllUsers or AuthenticatedUsers

**IAM Users**
- Identifies users with no MFA enabled
- Flags access keys older than 90 days

**EC2 Security Groups**
- Detects security groups with ports open to 0.0.0.0/0 (the entire internet)

## Sample Output
```
==================================================
AWS SECURITY AUDIT REPORT
Generated: 2026-03-09 10:09:20
==================================================

Checking S3 Buckets...
Checking IAM Users...
Checking Security Groups...

--- FINDINGS ---
✅ No major issues found!

Total issues found: 0
==================================================
```

## Tech Stack

- **Language:** Python 3.12
- **Cloud:** AWS Lambda, EventBridge, IAM, S3, EC2
- **SDK:** Boto3
- **Scheduling:** EventBridge Cron (`0 8 ? * MON *`)
- **Region:** eu-central-1 (Frankfurt)

## Deployment

1. Clone the repository
2. Deploy `security_auditor.py` to AWS Lambda (Python 3.12 runtime)
3. Attach the `SecurityAudit` IAM policy to the Lambda execution role
4. Create an EventBridge schedule with cron `0 8 ? * MON *` targeting the Lambda function

## IAM Permissions Required

The Lambda execution role requires the AWS managed `SecurityAudit` policy which 
provides read-only access to scan AWS services.

## Author

**Komon Ulrich Andy Fegue**  
AWS Certified Cloud Practitioner  
[LinkedIn](https://www.linkedin.com/in/komon-fegue-789746388/) | [GitHub](https://github.com/komonfegue6-ui)
