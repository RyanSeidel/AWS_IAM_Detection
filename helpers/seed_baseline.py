"""
Builds per-identity baselines in the insider-threat-baseline table.

    python helpers/seed_baseline.py
        Full scan: real CloudTrail history in every region. Removes stale profiles.

    python helpers/seed_baseline.py --from-file fake_events.json --merge-cloudtrail
        Synthetic history (gen_fake_history.py) for everyone with a persona,
        real CloudTrail history for everyone else. Removes stale profiles.

    python helpers/seed_baseline.py --from-file fake_events.json --only dana-test
        Resets one identity. Never touches anyone else's profile.
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

def fetch_cloudtrail_events():
    """Yields every scored event in the last 90 days of CloudTrail history, across all enabled regions."""
    ec2_client = boto3.client('ec2', region_name='us-east-1')
    regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]

    # LookupEvents accepts one filter per call, so ask for mutating events and
    # each sensitive read separately. This keeps MaxItems spent on relevant events.
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
                # Using PaginationConfig to limit pulls during testing.
                # Remove MaxItems for a full 90-day production scan.
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

def load_events_file(path):
    """Reads a JSON list of CloudTrail-shaped events, e.g. from gen_fake_history.py."""
    with open(path, encoding='utf-8') as f:
        return json.load(f)

def build_profiles(events):
    """
    Aggregates events into { identity_arn: {regions, hours, apis, source_ips} }.
    No filtering here: CloudTrail events are filtered when fetched, and a
    synthetic file is taken as-is because it describes exactly what's normal.
    """
    profiles = defaultdict(lambda: {"regions": set(), "hours": set(), "apis": set(), "source_ips": set()})

    for ct_event in events:
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

        profiles[identity]['regions'].add(event_region)
        profiles[identity]['apis'].add(api_call)
        if hour is not None:
            profiles[identity]['hours'].add(hour)

        ip = ip_key(ct_event.get('sourceIPAddress'))
        if ip is not None:
            profiles[identity]['source_ips'].add(ip)

    return dict(profiles)

def matches_only(identity, only):
    """--only takes a user name (dana-test) or a full ARN."""
    return identity == only or identity.endswith(f":user/{only}")

def write_profiles(profiles, remove_stale):
    table = boto3.resource('dynamodb', region_name='us-east-1').Table('insider-threat-baseline')

    # Remove profiles from earlier runs for identities with no scored activity
    # this time, so stale (e.g. read-only-polluted) profiles don't linger.
    # Only safe when this run covered everyone.
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
            # Sorted, so re-running with the same input writes an identical item
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
    parser.add_argument('--from-file', help="JSON list of events to build profiles from (e.g. fake_events.json)")
    parser.add_argument('--merge-cloudtrail', action='store_true',
                        help="with --from-file: also scan CloudTrail for identities not in the file")
    parser.add_argument('--only', help="write just this identity (user name or ARN); nobody else is touched")
    args = parser.parse_args()

    if args.merge_cloudtrail and not args.from_file:
        parser.error("--merge-cloudtrail needs --from-file")

    if args.from_file:
        profiles = build_profiles(load_events_file(args.from_file))
        print(f"Built {len(profiles)} profiles from {args.from_file}")
        if args.merge_cloudtrail:
            # Synthetic history wins: real test activity (high-risk calls,
            # late nights) must not leak into a persona's "normal".
            real = build_profiles(fetch_cloudtrail_events())
            added = {i: p for i, p in real.items() if i not in profiles}
            profiles.update(added)
            print(f"Added {len(added)} identities from CloudTrail that have no persona")
    else:
        profiles = build_profiles(fetch_cloudtrail_events())

    if args.only:
        profiles = {i: p for i, p in profiles.items() if matches_only(i, args.only)}
        if not profiles:
            raise SystemExit(f"No events for '{args.only}' in the input")

    # Deleting "stale" profiles is only safe when this run saw everyone.
    remove_stale = not args.only and (not args.from_file or args.merge_cloudtrail)

    print(f"\nWriting {len(profiles)} profiles to DynamoDB...")
    write_profiles(profiles, remove_stale)
    print("\nGlobal database initialization complete.")

if __name__ == "__main__":
    main()
