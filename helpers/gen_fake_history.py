import json
import random
import os
import glob
from datetime import datetime, timedelta

PERSONAS_DIR = "helpers/personas"
OUTPUT_FILE = "fake_events.json"

def generate_events_for_persona(persona):
    events = []
    end_date = datetime.utcnow()
    # Generate exactly 30 days of history
    start_date = end_date - timedelta(days=30)
    
    current_date = start_date
    while current_date <= end_date:
        # Enforce weekdays_only rule if set to true
        is_weekday = current_date.weekday() < 5
        if persona.get("weekdays_only") and not is_weekday:
            current_date += timedelta(days=1)
            continue
            
        # Determine daily volume using the persona's min/max bounds
        min_events, max_events = persona.get("events_per_day", [1, 5])
        daily_event_count = random.randint(min_events, max_events)
        
        for _ in range(daily_event_count):
            hour = random.choice(persona.get("hours_utc"))
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            event_time = current_date.replace(hour=hour, minute=minute, second=second)
            
            # Reconstruct the raw CloudTrail format (e.g., "s3" and "CreateBucket")
            api_call = random.choice(persona.get("apis"))
            source, name = api_call.split(":", 1)
                
            event = {
                "eventTime": event_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "eventSource": f"{source}.amazonaws.com",
                "eventName": name,
                "awsRegion": random.choice(persona.get("regions")),
                "sourceIPAddress": random.choice(persona.get("ips")),
                "userIdentity": {
                    "type": "IAMUser",
                    "arn": f"arn:aws:iam::021158484652:user/{persona['identity']}"
                }
            }
            events.append(event)
            
        current_date += timedelta(days=1)
    return events

def main():
    all_events = []
    persona_files = glob.glob(os.path.join(PERSONAS_DIR, "*.json"))
    
    if not persona_files:
        print(f"No persona files found in {PERSONAS_DIR}")
        return
        
    dana_persona = None
    teammate_personas = []
    
    # Read all files and separate dana-test from the rest
    for filepath in persona_files:
        with open(filepath, "r") as f:
            persona = json.load(f)
            if persona.get("identity") == "dana-test":
                dana_persona = persona
            else:
                teammate_personas.append(persona)
                
    # 1. Process dana first (Task 6B Requirement)
    if dana_persona:
        print(f"Generating history for {dana_persona['identity']}...")
        all_events.extend(generate_events_for_persona(dana_persona))
    else:
        print("Warning: dana-test.json not found in personas directory.")
        
    # 2. Process teammates from 6A
    for persona in teammate_personas:
        print(f"Generating history for {persona.get('identity', 'Unknown')}...")
        all_events.extend(generate_events_for_persona(persona))
            
    with open(OUTPUT_FILE, "w") as f:
        json.dump(all_events, f, indent=2)
        
    print(f"Generated {len(all_events)} total synthetic events in {OUTPUT_FILE}")

if __name__ == "__main__":
    main()