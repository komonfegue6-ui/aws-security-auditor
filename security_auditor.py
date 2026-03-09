import boto3
import json
from datetime import datetime

def check_s3_buckets():
    issues = []
    s3 = boto3.client('s3')
    buckets = s3.list_buckets()['Buckets']
    
    for bucket in buckets:
        name = bucket['Name']
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl['Grants']:
                if 'AllUsers' in str(grant) or 'AuthenticatedUsers' in str(grant):
                    issues.append(f"S3 RISK: Bucket '{name}' is publicly accessible")
        except Exception as e:
            issues.append(f"S3 WARNING: Could not check bucket '{name}': {str(e)}")
    
    return issues

def check_iam_users():
    issues = []
    iam = boto3.client('iam')
    users = iam.list_users()['Users']
    
    for user in users:
        username = user['UserName']
        # Check for users with no MFA
        mfa = iam.list_mfa_devices(UserName=username)['MFADevices']
        if not mfa:
            issues.append(f"IAM RISK: User '{username}' has no MFA enabled")
        
        # Check for old access keys
        keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
        for key in keys:
            if key['Status'] == 'Active':
                age = (datetime.now(key['CreateDate'].tzinfo) - key['CreateDate']).days
                if age > 90:
                    issues.append(f"IAM RISK: User '{username}' has access key older than 90 days ({age} days)")
    
    return issues

def check_security_groups():
    issues = []
    ec2 = boto3.client('ec2')
    sgs = ec2.describe_security_groups()['SecurityGroups']
    
    for sg in sgs:
        for rule in sg['IpPermissions']:
            for ip_range in rule.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    port = rule.get('FromPort', 'ALL')
                    issues.append(f"EC2 RISK: Security group '{sg['GroupName']}' allows port {port} open to the world")
    
    return issues

def generate_report():
    print("=" * 50)
    print("AWS SECURITY AUDIT REPORT")
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 50)
    
    all_issues = []
    
    print("\nChecking S3 Buckets...")
    s3_issues = check_s3_buckets()
    all_issues.extend(s3_issues)
    
    print("Checking IAM Users...")
    iam_issues = check_iam_users()
    all_issues.extend(iam_issues)
    
    print("Checking Security Groups...")
    sg_issues = check_security_groups()
    all_issues.extend(sg_issues)
    
    print("\n--- FINDINGS ---")
    if all_issues:
        for issue in all_issues:
            print(f"⚠️  {issue}")
    else:
        print("✅ No major issues found!")
    
    print(f"\nTotal issues found: {len(all_issues)}")
    print("=" * 50)

if __name__ == "__main__":
    generate_report()
