import json, os, boto3

sns = boto3.client("sns")
TOPIC = os.environ["ALERT_TOPIC"]

def resolve_identity(ui):
    t = ui.get("type")
    if t == "IAMUser":
        return ui.get("arn")
    if t == "AssumedRole":
        return ui.get("sessionContext", {}).get("sessionIssuer", {}).get("arn")
    return None

def handler(event, context):
    d = event.get("detail", {})
    ui = d.get("userIdentity", {})
    identity = resolve_identity(ui) or "unknown"
    api = "{}:{}".format(d.get("eventSource"), d.get("eventName"))

    body = (
        "Mutating API call detected\n\n"
        "Identity:   {}\n"
        "API:        {}\n"
        "Region:     {}\n"
        "Time (UTC): {}\n"
        "Source IP:  {}\n"
        "Access key: {}\n"
    ).format(identity, api, d.get("awsRegion"), d.get("eventTime"),
             d.get("sourceIPAddress"), ui.get("accessKeyId"))

    sns.publish(TopicArn=TOPIC, Subject="[insider-threat] {}".format(api)[:100], Message=body)
    print(json.dumps({"identity": identity, "api": api, "alerted": True}))
    return {"ok": True}