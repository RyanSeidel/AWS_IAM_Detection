import json
import os
import datetime
import ipaddress
import boto3
from boto3.dynamodb.conditions import Key

sns_client = boto3.client("sns")
dynamodb = boto3.resource("dynamodb")

TOPIC_ARN = os.environ["ALERT_TOPIC"]
TABLE_NAME = os.environ["BASELINE_TABLE"]

# ==========================================
# COMPOSITE SCORING WEIGHTS & THRESHOLDS
# ==========================================
ALERT_THRESHOLD = 75
WEIGHT_NEW_REGION = 35
WEIGHT_NEW_API = 20
WEIGHT_UNUSUAL_HOUR = 25
WEIGHT_NEW_IP = 25
WEIGHT_HIGH_RISK_API = 40
# An identity with no baseline profile is itself suspicious (e.g. a freshly
# created backdoor user). On its own it stays below the threshold; combined
# with any high-risk API it alerts.
WEIGHT_UNKNOWN_IDENTITY = 40
# Tampering with logging blinds the detector, so it alerts on its own.
WEIGHT_DEFENSE_EVASION = ALERT_THRESHOLD

# High-Risk APIs mapped to (MITRE ATT&CK Tactic, weight)
HIGH_RISK_APIS = {
    # Privilege Escalation & Persistence (T1098, T1078.004)
    "iam:CreateAccessKey": ("Persistence", WEIGHT_HIGH_RISK_API),
    "iam:PutUserPolicy": ("Privilege Escalation", WEIGHT_HIGH_RISK_API),
    "iam:AttachUserPolicy": ("Privilege Escalation", WEIGHT_HIGH_RISK_API),
    "iam:AttachRolePolicy": ("Privilege Escalation", WEIGHT_HIGH_RISK_API),
    "iam:PutRolePolicy": ("Privilege Escalation", WEIGHT_HIGH_RISK_API),
    "iam:CreateLoginProfile": ("Persistence", WEIGHT_HIGH_RISK_API),
    "iam:UpdateLoginProfile": ("Persistence", WEIGHT_HIGH_RISK_API),
    # Defense Evasion (T1562.001)
    "cloudtrail:StopLogging": ("Defense Evasion", WEIGHT_DEFENSE_EVASION),
    "cloudtrail:DeleteTrail": ("Defense Evasion", WEIGHT_DEFENSE_EVASION),
    "cloudtrail:UpdateTrail": ("Defense Evasion", WEIGHT_DEFENSE_EVASION),
    "cloudtrail:PutEventSelectors": ("Defense Evasion", WEIGHT_DEFENSE_EVASION),
    # Resource Hijacking / Execution (T1496)
    "ec2:RunInstances": ("Resource Hijacking", WEIGHT_HIGH_RISK_API),
    "lambda:CreateFunction": ("Execution / Persistence", WEIGHT_HIGH_RISK_API),
    # Exfiltration via sharing or exposure (T1537, T1530)
    "s3:PutBucketPolicy": ("Exfiltration", WEIGHT_HIGH_RISK_API),
    "s3:PutBucketAcl": ("Exfiltration", WEIGHT_HIGH_RISK_API),
    "s3:PutBucketReplication": ("Exfiltration", WEIGHT_HIGH_RISK_API),
    "s3:DeleteBucketPublicAccessBlock": ("Exfiltration", WEIGHT_HIGH_RISK_API),
    "ec2:ModifySnapshotAttribute": ("Exfiltration", WEIGHT_HIGH_RISK_API),
    "ec2:ModifyImageAttribute": ("Exfiltration", WEIGHT_HIGH_RISK_API),
    "rds:ModifyDBSnapshotAttribute": ("Exfiltration", WEIGHT_HIGH_RISK_API),
    # Credential Access: reading stored secrets (T1552)
    "ssm:GetParameter": ("Credential Access", WEIGHT_HIGH_RISK_API),
    "ssm:GetParameters": ("Credential Access", WEIGHT_HIGH_RISK_API),
    "secretsmanager:GetSecretValue": ("Credential Access", WEIGHT_HIGH_RISK_API),
    # Collection (T1530). Only arrives if CloudTrail data events are enabled
    # for a bucket, e.g. a decoy bucket, so any read of it is suspicious.
    "s3:GetObject": ("Collection", WEIGHT_HIGH_RISK_API)
}

def resolve_identity(ui):
    """Extracts the underlying human or role identity from the CloudTrail UserIdentity object."""
    t = ui.get("type")
    if t == "IAMUser":
        return ui.get("arn")
    if t == "AssumedRole":
        return ui.get("sessionContext", {}).get("sessionIssuer", {}).get("arn")
    if t == "Root":
        return ui.get("arn")
    return None

def parse_ip(value):
    """Returns the IP string, or None when sourceIPAddress is a hostname (e.g. 's3.amazonaws.com')."""
    try:
        return str(ipaddress.ip_address(value))
    except (TypeError, ValueError):
        return None

def fetch_baseline(identity):
    """
    Queries DynamoDB using the 'identity' partition key to retrieve historical baseline sets.
    Assumes the baseline generator (helpers/seed_baseline.py) populates a 'profile' facet.
    Returns None if the identity has no profile. Lookup errors propagate to the caller.
    """
    table = dynamodb.Table(TABLE_NAME)
    response = table.query(
        KeyConditionExpression=Key('identity').eq(identity)
    )
    items = response.get('Items', [])

    profile = next((item for item in items if item.get('facet') == 'profile'), None)
    if profile is None:
        return None

    return {
        "known_regions": set(profile.get("regions", [])),
        "known_apis": set(profile.get("apis", [])),
        # Seeded hours may come back as Decimal; normalise to int for comparison
        "normal_hours": {int(h) for h in profile.get("hours", [])},
        "known_ips": set(profile.get("source_ips", []))
    }

def handler(event, context):
    d = event.get("detail", {})
    ui = d.get("userIdentity", {})
    identity = resolve_identity(ui) or "unknown"
    
    event_source = d.get("eventSource", "").split(".")[0]  # e.g., 'iam' from 'iam.amazonaws.com'
    event_name = d.get("eventName", "Unknown")
    api_call = f"{event_source}:{event_name}"
    
    region = d.get("awsRegion", "unknown")
    source_ip = d.get("sourceIPAddress")
    event_time_str = d.get("eventTime", "")
    
    # Parse event hour (UTC)
    try:
        event_hour = datetime.datetime.strptime(event_time_str, "%Y-%m-%dT%H:%M:%SZ").hour
    except ValueError:
        event_hour = None
        
    # 1. Fetch historical behavioral baseline
    baseline_error = None
    try:
        baseline = fetch_baseline(identity)
    except Exception as e:
        print(f"Error fetching baseline for {identity}: {e}")
        baseline, baseline_error = None, e

    # 2. Evaluate Anomalies & Calculate Composite Score
    score = 0
    anomalies = []
    mitre_tactics = []

    # Check High-Risk Static API (Contextual Threat)
    if api_call in HIGH_RISK_APIS:
        tactic, weight = HIGH_RISK_APIS[api_call]
        score += weight
        mitre_tactics.append(tactic)
        anomalies.append(f"Highly sensitive operation mapped to MITRE ATT&CK ({tactic}).")

    if baseline_error is not None:
        # Fail closed: if we can't judge the event, surface it rather than drop it
        score = max(score, ALERT_THRESHOLD)
        anomalies.append(f"Baseline lookup failed ({baseline_error}); event could not be scored.")
    elif baseline is None:
        score += WEIGHT_UNKNOWN_IDENTITY
        anomalies.append("Identity has no behavioral baseline (never seen before).")
    else:
        # Check API usage history
        if baseline["known_apis"] and api_call not in baseline["known_apis"]:
            score += WEIGHT_NEW_API
            anomalies.append(f"First time this identity has invoked the '{api_call}' service operation.")

        # Check regional deviation
        if baseline["known_regions"] and region not in baseline["known_regions"]:
            score += WEIGHT_NEW_REGION
            anomalies.append(f"Execution in uncharacteristic AWS region: {region}.")

        # Check temporal deviation
        if baseline["normal_hours"] and event_hour is not None and event_hour not in baseline["normal_hours"]:
            score += WEIGHT_UNUSUAL_HOUR
            anomalies.append(f"Activity outside normal working hours (Hour {event_hour} UTC).")

        # Check source IP: a stolen key is usually used from the attacker's machine
        ip = parse_ip(source_ip)
        if baseline["known_ips"] and ip is not None and ip not in baseline["known_ips"]:
            score += WEIGHT_NEW_IP
            anomalies.append(f"Call made from an IP address never seen for this identity: {ip}.")
        
    # 3. Decision Engine: Alert via SNS if threshold is breached
    if score >= ALERT_THRESHOLD:
        mitre_string = ", ".join(mitre_tactics) if mitre_tactics else "N/A"
        explanations = "\n- ".join(anomalies)
        
        body = (
            f"URGENT: Insider Threat Alert - Risk Score [{score}]\n"
            f"--------------------------------------------------\n"
            f"Identity:     {identity}\n"
            f"API Call:     {api_call}\n"
            f"Region:       {region}\n"
            f"Time (UTC):   {event_time_str}\n"
            f"Source IP:    {source_ip}\n"
            f"MITRE Tactic: {mitre_string}\n\n"
            f"Why this alert fired:\n"
            f"- {explanations}\n\n"
            f"Action Required: Verify intent with identity owner. If unauthorized, revoke active IAM sessions immediately."
        )
        
        subject = f"[Severity: HIGH] Suspicious IAM Behavior Detected: {api_call}"[:100]
        sns_client.publish(TopicArn=TOPIC_ARN, Subject=subject, Message=body)

    print(json.dumps({
        "identity": identity,
        "api": api_call,
        "region": region,
        "source_ip": source_ip,
        "score": score,
        "alerted": score >= ALERT_THRESHOLD,
        "tactics": mitre_tactics,
        "reasons": anomalies
    }))

    return {"statusCode": 200, "body": "Evaluation complete."}