"""
Builds per-identity baselines in the insider-threat-baseline table.

    python helpers/seed_baseline.py
        Full scan: real CloudTrail history in every region. Removes stale profiles.

    python helpers/seed_baseline.py --personas --merge-cloudtrail
        Persona files (helpers/personas/*.json) for everyone who has one,
        real CloudTrail history for everyone else. Removes stale profiles.

    python helpers/seed_baseline.py --personas --only dana-test
        Resets one identity from its persona file. Never touches anyone else's profile.

Persona baselines are synthetic: they describe each person's normal, they
aren't a record of what they did. Say so in the demo.
"""
import argparse
import glob
import json
import datetime
import ipaddress
import os
import re
import boto3
from collections import defaultdict

# One hand-written profile per identity (helpers/personas/<iam-user>.json).
PERSONA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "personas")

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

def normalize_api(api):
    """'lambda:CreateFunction20150331' -> 'lambda:CreateFunction', matching the scan and the Lambda."""
    service, _, name = api.partition(':')
    return f"{service}:{API_VERSION_SUFFIX.sub('', name)}"

def load_personas(account_id):
    """
    Reads every helpers/personas/*.json into the same profile shape that
    build_profiles makes. 'identity' may be an IAM user name or a full ARN.
    events_per_day and weekdays_only document the persona; the Lambda doesn't
    score volume or weekdays, so they aren't stored.
    """
    personas = {}
    for path in sorted(glob.glob(os.path.join(PERSONA_DIR, "*.json"))):
        name = os.path.basename(path)
        with open(path, encoding='utf-8') as f:
            p = json.load(f)

        identity = p['identity']
        if not identity.startswith('arn:'):
            identity = f"arn:aws:iam::{account_id}:user/{identity}"

        ips = set()
        for value in p.get('ips', []):
            key = ip_key(value)
            if key is None:
                print(f"  -> {name}: '{value}' is not an IP address, skipped")
            else:
                ips.add(key)

        personas[identity] = {
            "regions": set(p.get('regions', [])),
            "hours": {int(h) for h in p.get('hours_utc', [])},
            "apis": {normalize_api(a) for a in p.get('apis', [])},
            "source_ips": ips,
        }
        print(f"Loaded persona {name} -> {identity}")
    return personas

def build_profiles(events):
    """Aggregates (already filtered) CloudTrail events into { identity_arn: {regions, hours, apis, source_ips} }."""
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
    parser.add_argument('--personas', action='store_true',
                        help="build profiles from helpers/personas/*.json instead of CloudTrail")
    parser.add_argument('--merge-cloudtrail', action='store_true',
                        help="with --personas: also scan CloudTrail for identities without a persona")
    parser.add_argument('--only', help="write just this identity (user name or ARN); nobody else is touched")
    args = parser.parse_args()

    if args.merge_cloudtrail and not args.personas:
        parser.error("--merge-cloudtrail needs --personas")

    if args.personas:
        account_id = boto3.client('sts').get_caller_identity()['Account']
        profiles = load_personas(account_id)
        print(f"Built {len(profiles)} profiles from persona files")
        if args.merge_cloudtrail:
            # Personas win: real test activity (high-risk calls, late
            # nights) must not leak into a persona's "normal".
            real = build_profiles(fetch_cloudtrail_events())
            added = {i: p for i, p in real.items() if i not in profiles}
            profiles.update(added)
            print(f"Added {len(added)} identities from CloudTrail that have no persona")
    else:
        profiles = build_profiles(fetch_cloudtrail_events())

    if args.only:
        profiles = {i: p for i, p in profiles.items() if matches_only(i, args.only)}
        if not profiles:
            raise SystemExit(f"No profile for '{args.only}' in the input")

    # Deleting "stale" profiles is only safe when this run saw everyone.
    remove_stale = not args.only and (not args.personas or args.merge_cloudtrail)

    print(f"\nWriting {len(profiles)} profiles to DynamoDB...")
    write_profiles(profiles, remove_stale)
    print("\nGlobal database initialization complete.")

if __name__ == "__main__":
    main()
