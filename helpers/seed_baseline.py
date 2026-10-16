"""
Builds per-identity baselines in the insider-threat-baseline table.

    python helpers/seed_baseline.py
        Full scan: real CloudTrail history in every region. Removes stale profiles.

    python helpers/seed_baseline.py --from-file fake_events.json --merge-cloudtrail
        Reads synthetic events from a JSON file, and merges real CloudTrail 
        history for anyone not in the file. Removes stale profiles.

    python helpers/seed_baseline.py --from-file fake_events.json --only dana-test
        Resets one identity from its synthetic history. Nobody else is touched.
"""
import argparse
import json
import datetime
import ipaddress
import re
import boto3
from collections import defaultdict

# Must match lambda/handler.py: strips API version suffixes such as
# Lambda's 'CreateFunction20150331' so baseline and detector agree on names.
API_VERSION_SUFFIX = re.compile(r"\d{4}_?\d{2}_?\d{2}(v\d+)?$")

SENSITIVE_READS = ["GetParameter", "GetParameters", "GetSecretValue", "GetObject"]

def ip_key(value):
    try:
        if "/" in value:
            return str(ipaddress.ip_network(value, strict=False))
        ip = ipaddress.ip_address(value)
    except (TypeError, ValueError):
        return None
    if ip.version == 6:
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    return str(ip)

def resolve_identity(ui):
    t = ui.get('type')
    if t == 'IAMUser' or t == 'Root':
        return ui.get('arn')
    if t == 'AssumedRole':
        return ui.get('sessionContext', {}).get('sessionIssuer', {}).get('arn')
    return None

def is_scored_event(ct_event):
    if ct_event.get('eventSource') == 'logs.amazonaws.com':
        return False
    if 'invokedBy' in ct_event.get('userIdentity', {}):
        return False
    return ct_event.get('readOnly') is False or ct_event.get('eventName') in SENSITIVE_READS

def fetch_cloudtrail_events():
    ec2_client = boto3.client('ec2', region_name='us-east-1')
    regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]

    lookups = [{'AttributeKey': 'ReadOnly', 'AttributeValue': 'false'}] + [
        {'AttributeKey': 'EventName', 'AttributeValue': name} for name in SENSITIVE_READS
    ]

    print(f"Discovered {len(regions)} active regions. Beginning global CloudTrail baseline extraction...")

    for region in regions:
        print(f"Scanning region: {region}...")
        try:
            cloudtrail = boto3.client('cloudtrail', region_name=region)
            paginator = cloudtrail.get_paginator('lookup_events')

            for lookup in lookups:
                page_iterator = paginator.paginate(
                    LookupAttributes=[lookup],
                    PaginationConfig={'MaxItems': 10000}
                )
                for page in page_iterator:
                    for event in page.get('Events', []):
                        ct_event = json.loads(event.get('CloudTrailEvent', '{}'))
                        if is_scored_event(ct_event):
                            yield ct_event

        except Exception as e:
            print(f"  -> Error or access denied fetching logs in {region}: {e}")

def build_profiles(events):
    profiles = defaultdict(lambda: {"regions": set(), "hours": set(), "apis": set(), "source_ips": set()})

    for ct_event in events:
        identity = resolve_identity(ct_event.get('userIdentity', {}))
        if not identity:
            continue

        event_source = ct_event.get('eventSource', '').split('.')[0]
        event_name = API_VERSION_SUFFIX.sub('', ct_event.get('eventName', 'Unknown'))
        api_call = f"{event_source}:{event_name}"
        event_region = ct_event.get('awsRegion', 'unknown')

        time_str = ct_event.get('eventTime', '')
        try:
            hour = datetime.datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%SZ").hour
        except ValueError:
            hour = None

        profiles[identity]['regions'].add(event_region)
        profiles[identity]['apis'].add(api_call)
        if hour is not None:
            profiles[identity]['hours'].add(hour)

        ip = ip_key(ct_event.get('sourceIPAddress'))
        if ip is not None:
            profiles[identity]['source_ips'].add(ip)

    return dict(profiles)

def matches_only(identity, only):
    return identity == only or identity.endswith(f":user/{only}")

def write_profiles(profiles, remove_stale):
    table = boto3.resource('dynamodb', region_name='us-east-1').Table('insider-threat-baseline')

    stale = []
    if remove_stale:
        scan_kwargs = {'ProjectionExpression': '#i, facet', 'ExpressionAttributeNames': {'#i': 'identity'}}
        while True:
            page = table.scan(**scan_kwargs)
            stale += [item['identity'] for item in page.get('Items', [])
                      if item.get('facet') == 'profile' and item['identity'] not in profiles]
            if 'LastEvaluatedKey' not in page:
                break
            scan_kwargs['ExclusiveStartKey'] = page['LastEvaluatedKey']

    with table.batch_writer() as batch:
        for identity in stale:
            batch.delete_item(Key={"identity": identity, "facet": "profile"})
            print(f"🗑️  Removed stale profile: {identity}")
        for identity, data in profiles.items():
            item = {
                "identity": identity,
                "facet": "profile",
                "regions": sorted(data["regions"]),
                "hours": sorted(data["hours"]),
                "apis": sorted(data["apis"]),
                "source_ips": sorted(data["source_ips"])
            }
            batch.put_item(Item=item)
            print(f"✅ Baselined identity: {identity}")

def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--from-file', help="load simulated CloudTrail events from a JSON file")
    parser.add_argument('--merge-cloudtrail', action='store_true',
                        help="with --from-file: also scan CloudTrail for identities not in the file")
    parser.add_argument('--only', help="write just this identity (user name or ARN); nobody else is touched")
    args = parser.parse_args()

    if args.merge_cloudtrail and not args.from_file:
        parser.error("--merge-cloudtrail needs --from-file")

    if args.from_file:
        with open(args.from_file, 'r', encoding='utf-8') as f:
            file_events = json.load(f)
            
        profiles = build_profiles(file_events)
        print(f"Built {len(profiles)} profiles from {args.from_file}")
        
        if args.merge_cloudtrail:
            real_profiles = build_profiles(fetch_cloudtrail_events())
            added = {i: p for i, p in real_profiles.items() if i not in profiles}
            profiles.update(added)
            print(f"Added {len(added)} identities from CloudTrail that have no synthetic history")
    else:
        profiles = build_profiles(fetch_cloudtrail_events())

    if args.only:
        profiles = {i: p for i, p in profiles.items() if matches_only(i, args.only)}
        if not profiles:
            raise SystemExit(f"No profile for '{args.only}' in the input")

    remove_stale = not args.only and (not args.from_file or args.merge_cloudtrail)

    print(f"\nWriting {len(profiles)} profiles to DynamoDB...")
    write_profiles(profiles, remove_stale)
    print("\nGlobal database initialization complete.")

if __name__ == "__main__":
    main()