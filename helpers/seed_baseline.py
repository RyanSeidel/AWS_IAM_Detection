import json
import datetime
import boto3
from collections import defaultdict

def seed_real_world_global_baselines():
    # 1. Dynamically fetch all enabled regions for this AWS account
    ec2_client = boto3.client('ec2', region_name='us-east-1')
    regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
    
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.Table('insider-threat-baseline')
    
    # Structure: { identity_arn: { "regions": set(), "hours": set(), "apis": set() } }
    profiles = defaultdict(lambda: {"regions": set(), "hours": set(), "apis": set()})
    
    print(f"Discovered {len(regions)} active regions. Beginning global CloudTrail baseline extraction...")
    
    # 2. Iterate through every region to pull localized CloudTrail events
    for region in regions:
        print(f"Scanning region: {region}...")
        try:
            # Create a region-specific CloudTrail client
            cloudtrail = boto3.client('cloudtrail', region_name=region)
            paginator = cloudtrail.get_paginator('lookup_events')
            
            # Using PaginationConfig to limit pulls during testing. 
            # Remove MaxItems for a full 90-day production scan.
            page_iterator = paginator.paginate(
                PaginationConfig={'MaxItems': 10000} 
            )
            
            for page in page_iterator:
                for event in page.get('Events', []):
                    ct_event = json.loads(event.get('CloudTrailEvent', '{}'))
                    
                    # Resolve Identity
                    ui = ct_event.get('userIdentity', {})
                    user_type = ui.get('type')
                    
                    identity = None
                    if user_type == 'IAMUser':
                        identity = ui.get('arn')
                    elif user_type == 'AssumedRole':
                        identity = ui.get('sessionContext', {}).get('sessionIssuer', {}).get('arn')
                    
                    if not identity:
                        continue 
                        
                    # Extract Behavioral Data Points
                    event_source = ct_event.get('eventSource', '').split('.')[0]
                    event_name = ct_event.get('eventName', 'Unknown')
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
                        
        except Exception as e:
            print(f"  -> Error or access denied fetching logs in {region}: {e}")

    print(f"\nProcessed global logs. Found {len(profiles)} unique identities. Writing to DynamoDB...")

    # 3. Write the aggregated global profiles to DynamoDB
    with table.batch_writer() as batch:
        for identity, data in profiles.items():
            item = {
                "identity": identity,
                "facet": "profile",
                "regions": list(data["regions"]),
                "hours": list(data["hours"]),
                "apis": list(data["apis"])
            }
            batch.put_item(Item=item)
            print(f"✅ Baselined identity: {identity}")
            
    print("\nGlobal database initialization complete.")

if __name__ == "__main__":
    seed_real_world_global_baselines()