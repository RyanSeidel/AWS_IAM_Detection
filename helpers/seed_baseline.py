import json
import datetime
import ipaddress
import re
import boto3
from collections import defaultdict

# Must match lambda/handler.py: strips API version suffixes such as
# Lambda's 'CreateFunction20150331' so baseline and detector agree on names.
API_VERSION_SUFFIX = re.compile(r"\d{4}_?\d{2}_?\d{2}(v\d+)?$")

# Must match the EventBridge rule in main/eventbridge.tf. The baseline only
# learns from events the detector actually scores: mutating calls plus these
# sensitive reads. Learning from every read (console browsing, this script's
# own LookupEvents calls) would make every region and API look "normal".
SENSITIVE_READS = ["GetParameter", "GetParameters", "GetSecretValue", "GetObject"]

def ip_key(value):
    """
    Must match lambda/handler.py. IPv4 is kept exact; IPv6 is reduced to its
    /64 network, because home routers rotate the rest of the address.
    Returns None for hostnames (service calls put e.g. 's3.amazonaws.com' here).
    """
    try:
        if "/" in value:
            # Already normalised (a stored IPv6 /64 network)
            return str(ipaddress.ip_network(value, strict=False))
        ip = ipaddress.ip_address(value)
    except (TypeError, ValueError):
        return None
    if ip.version == 6:
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    return str(ip)

def resolve_identity(ui):
    """Must match lambda/handler.py."""
    t = ui.get('type')
    if t == 'IAMUser' or t == 'Root':
        return ui.get('arn')
    if t == 'AssumedRole':
        return ui.get('sessionContext', {}).get('sessionIssuer', {}).get('arn')
    return None

def is_scored_event(ct_event):
    """Mirrors the EventBridge filter, so we only learn from events the detector sees."""
    if ct_event.get('eventSource') == 'logs.amazonaws.com':
        return False
    if 'invokedBy' in ct_event.get('userIdentity', {}):
        return False
    return ct_event.get('readOnly') is False or ct_event.get('eventName') in SENSITIVE_READS

def seed_real_world_global_baselines():
    # 1. Dynamically fetch all enabled regions for this AWS account
    ec2_client = boto3.client('ec2', region_name='us-east-1')
    regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]

    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.Table('insider-threat-baseline')

    # Structure: { identity_arn: { "regions": set(), "hours": set(), "apis": set(), "source_ips": set() } }
    profiles = defaultdict(lambda: {"regions": set(), "hours": set(), "apis": set(), "source_ips": set()})

    # LookupEvents accepts one filter per call, so ask for mutating events and
    # each sensitive read separately. This keeps MaxItems spent on relevant events.
    lookups = [{'AttributeKey': 'ReadOnly', 'AttributeValue': 'false'}] + [
        {'AttributeKey': 'EventName', 'AttributeValue': name} for name in SENSITIVE_READS
    ]

    print(f"Discovered {len(regions)} active regions. Beginning global CloudTrail baseline extraction...")

    # 2. Iterate through every region to pull localized CloudTrail events
    for region in regions:
        print(f"Scanning region: {region}...")
        try:
            # Create a region-specific CloudTrail client
            cloudtrail = boto3.client('cloudtrail', region_name=region)
            paginator = cloudtrail.get_paginator('lookup_events')

            for lookup in lookups:
                # Using PaginationConfig to limit pulls during testing.
                # Remove MaxItems for a full 90-day production scan.
                page_iterator = paginator.paginate(
                    LookupAttributes=[lookup],
                    PaginationConfig={'MaxItems': 10000}
                )

                for page in page_iterator:
                    for event in page.get('Events', []):
                        ct_event = json.loads(event.get('CloudTrailEvent', '{}'))
                        if not is_scored_event(ct_event):
                            continue

                        identity = resolve_identity(ct_event.get('userIdentity', {}))
                        if not identity:
                            continue

                        # Extract Behavioral Data Points
                        event_source = ct_event.get('eventSource', '').split('.')[0]
                        event_name = API_VERSION_SUFFIX.sub('', ct_event.get('eventName', 'Unknown'))
                        api_call = f"{event_source}:{event_name}"
                        event_region = ct_event.get('awsRegion', 'unknown')

                        time_str = ct_event.get('eventTime', '')
                        try:
                            hour = datetime.datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%SZ").hour
                        except ValueError:
                            hour = None

                        # Add observed data to the identity's profile
                        profiles[identity]['regions'].add(event_region)
                        profiles[identity]['apis'].add(api_call)
                        if hour is not None:
                            profiles[identity]['hours'].add(hour)

                        ip = ip_key(ct_event.get('sourceIPAddress'))
                        if ip is not None:
                            profiles[identity]['source_ips'].add(ip)

        except Exception as e:
            print(f"  -> Error or access denied fetching logs in {region}: {e}")

    print(f"\nProcessed global logs. Found {len(profiles)} unique identities. Writing to DynamoDB...")

    # 3. Remove profiles from earlier runs for identities with no scored activity
    #    this time, so stale (e.g. read-only-polluted) profiles don't linger.
    stale = []
    scan_kwargs = {'ProjectionExpression': '#i, facet', 'ExpressionAttributeNames': {'#i': 'identity'}}
    while True:
        page = table.scan(**scan_kwargs)
        stale += [item['identity'] for item in page.get('Items', [])
                  if item.get('facet') == 'profile' and item['identity'] not in profiles]
        if 'LastEvaluatedKey' not in page:
            break
        scan_kwargs['ExclusiveStartKey'] = page['LastEvaluatedKey']

    # 4. Write the aggregated global profiles to DynamoDB
    with table.batch_writer() as batch:
        for identity in stale:
            batch.delete_item(Key={"identity": identity, "facet": "profile"})
            print(f"🗑️  Removed stale profile: {identity}")
        for identity, data in profiles.items():
            item = {
                "identity": identity,
                "facet": "profile",
                "regions": list(data["regions"]),
                "hours": list(data["hours"]),
                "apis": list(data["apis"]),
                "source_ips": list(data["source_ips"])
            }
            batch.put_item(Item=item)
            print(f"✅ Baselined identity: {identity}")

    print("\nGlobal database initialization complete.")

if __name__ == "__main__":
    seed_real_world_global_baselines()
