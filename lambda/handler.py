import json
import os
import datetime
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
WEIGHT_HIGH_RISK_API = 40

# High-Risk APIs mapped to MITRE ATT&CK Tactics
HIGH_RISK_APIS = {
    # Privilege Escalation & Persistence (T1098, T1078.004)
    "iam:CreateAccessKey": "Persistence",
    "iam:PutUserPolicy": "Privilege Escalation",
    "iam:AttachUserPolicy": "Privilege Escalation",
    "iam:AttachRolePolicy": "Privilege Escalation",
    "iam:PutRolePolicy": "Privilege Escalation",
    "iam:CreateLoginProfile": "Persistence",
    "iam:UpdateLoginProfile": "Persistence",
    # Defense Evasion (T1562.001)
    "cloudtrail:StopLogging": "Defense Evasion",
    "cloudtrail:DeleteTrail": "Defense Evasion",
    "cloudtrail:UpdateTrail": "Defense Evasion",
    # Resource Hijacking / Execution (T1496)
    "ec2:RunInstances": "Resource Hijacking",
    "lambda:CreateFunction": "Execution / Persistence"
}

def resolve_identity(ui):
    """Extracts the underlying human or role identity from the CloudTrail UserIdentity object."""
    t = ui.get("type")
    if t == "IAMUser":
        return ui.get("arn")
    if t == "AssumedRole":
        return ui.get("sessionContext", {}).get("sessionIssuer", {}).get("arn")
    return None

def fetch_baseline(identity):
    """
    Queries DynamoDB using the 'identity' partition key to retrieve historical baseline sets.
    Assumes the baseline generator populates a 'profile' facet.
    """
    table = dynamodb.Table(TABLE_NAME)
    
    try:
        response = table.query(
            KeyConditionExpression=Key('identity').eq(identity)
        )
        items = response.get('Items', [])
        
        # Look for the consolidated profile facet, or default to empty lists
        profile = next((item for item in items if item.get('facet') == 'profile'), {})
        
        return {
            "known_regions": set(profile.get("regions", [])),
            "known_apis": set(profile.get("apis", [])),
            "normal_hours": set(profile.get("hours", []))
        }
    except Exception as e:
        print(f"Error fetching baseline for {identity}: {e}")
        return {"known_regions": set(), "known_apis": set(), "normal_hours": set()}

def handler(event, context):
    d = event.get("detail", {})
    ui = d.get("userIdentity", {})
    identity = resolve_identity(ui) or "unknown"
    
    event_source = d.get("eventSource", "").split(".")[0]  # e.g., 'iam' from 'iam.amazonaws.com'
    event_name = d.get("eventName", "Unknown")
    api_call = f"{event_source}:{event_name}"
    
    region = d.get("awsRegion", "unknown")
    event_time_str = d.get("eventTime", "")
    
    # Parse event hour (UTC)
    try:
        event_hour = datetime.datetime.strptime(event_time_str, "%Y-%m-%dT%H:%M:%SZ").hour
    except ValueError:
        event_hour = None
        
    # 1. Fetch historical behavioral baseline
    baseline = fetch_baseline(identity)
    
    # 2. Evaluate Anomalies & Calculate Composite Score
    score = 0
    anomalies = []
    mitre_tactics = []
    
    # Check High-Risk Static API (Contextual Threat)
    if api_call in HIGH_RISK_APIS:
        score += WEIGHT_HIGH_RISK_API
        tactic = HIGH_RISK_APIS[api_call]
        mitre_tactics.append(tactic)
        anomalies.append(f"Highly sensitive operation mapped to MITRE ATT&CK ({tactic}).")
        
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
            f"Source IP:    {d.get('sourceIPAddress')}\n"
            f"MITRE Tactic: {mitre_string}\n\n"
            f"Why this alert fired:\n"
            f"- {explanations}\n\n"
            f"Action Required: Verify intent with identity owner. If unauthorized, revoke active IAM sessions immediately."
        )
        
        subject = f"[Severity: HIGH] Suspicious IAM Behavior Detected: {api_call}"[:100]
        sns_client.publish(TopicArn=TOPIC_ARN, Subject=subject, Message=body)
        
        print(json.dumps({"identity": identity, "api": api_call, "score": score, "alerted": True}))
    else:
        print(json.dumps({"identity": identity, "api": api_call, "score": score, "alerted": False}))
        
    return {"statusCode": 200, "body": "Evaluation complete."}