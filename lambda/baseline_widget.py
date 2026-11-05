"""
"What's normal" panel for the InsiderWatch dashboard (CloudWatch custom widget).

CloudWatch calls this Lambda with the viewer's own credentials, so only
people allowed to invoke it (admins, insider-threat-analysts) see anything.
It returns HTML: one button per baselined identity, and the selected
identity's regions, IPs, hours and APIs with the points a new value adds.

Reads the baseline the same way the detector does (handler.fetch_baseline)
and uses the detector's weights, so the numbers can't drift from the scoring.
"""
import html
import json

import handler as detector

DOCS = """## What's normal (baseline)
Shows each identity's baseline from the insider-threat-baseline table, and
how many points a value outside it adds to an event's score.
"""


def list_identities():
    """Every identity with a baseline profile, sorted by display name."""
    table = detector.dynamodb.Table(detector.TABLE_NAME)
    kwargs = {"ProjectionExpression": "#i, facet", "ExpressionAttributeNames": {"#i": "identity"}}
    identities = []
    while True:
        page = table.scan(**kwargs)
        identities += [i["identity"] for i in page.get("Items", []) if i.get("facet") == "profile"]
        if "LastEvaluatedKey" not in page:
            break
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]
    return sorted(identities, key=short_name)


def short_name(arn):
    """'arn:aws:iam::123:user/dana-test' -> 'dana-test', 'arn:aws:iam::123:root' -> 'root'."""
    return arn.rsplit("/", 1)[-1] if "/" in arn else arn.rsplit(":", 1)[-1]


def hour_range(hours):
    """'13:00–23:00 UTC': from the first active hour to the end of the last one."""
    if not hours:
        return "none recorded"
    return f"{min(hours):02d}:00–{max(hours) + 1:02d}:00 UTC"


def chips(values, empty="none recorded"):
    if not values:
        return f'<span style="opacity:.6">{empty}</span>'
    return " ".join(
        f'<span style="display:inline-block;margin:2px;padding:2px 8px;border-radius:10px;'
        f'border:1px solid #8fbf9f;background:rgba(46,160,67,.12)">{html.escape(str(v))}</span>'
        for v in sorted(values)
    )


def hour_strip(active):
    cells = []
    for h in range(24):
        on = h in active
        style = ("background:#3b6fd8;color:#fff" if on
                 else "background:rgba(128,128,128,.15);opacity:.6")
        cells.append(f'<span style="display:inline-block;width:3.6%;margin:1px;padding:3px 0;'
                     f'text-align:center;border-radius:3px;{style}">{h}</span>')
    return "".join(cells)


def section(title, body, rule):
    return (f'<div style="margin:10px 0"><b>{title}</b><div style="margin:4px 0">{body}</div>'
            f'<div style="font-size:12px;opacity:.75">{rule}</div></div>')


def identity_buttons(identities, selected, endpoint):
    out = []
    for arn in identities:
        cls = "btn btn-primary" if arn == selected else "btn"
        out.append(f'<a class="{cls}" style="margin:2px">{html.escape(short_name(arn))}</a>'
                   f'<cwdb-action action="call" endpoint="{html.escape(endpoint)}" display="widget">'
                   f'{html.escape(json.dumps({"identity": arn}))}</cwdb-action>')
    return " ".join(out)


def render(identities, selected, profile, endpoint):
    top = identity_buttons(identities, selected, endpoint)
    if not selected:
        return top + "<p>No baselines yet. Run helpers/seed_baseline.py.</p>"

    header = f'<p style="margin:8px 0 0">Baseline for <code>{html.escape(selected)}</code></p>'
    if profile is None:
        return top + header + (f"<p>No baseline for this identity. Any event from it "
                               f"scores +{detector.WEIGHT_UNKNOWN_IDENTITY}.</p>")

    return top + header + "".join([
        section("Regions", chips(profile["known_regions"]),
                f"Any other region: <b>+{detector.WEIGHT_NEW_REGION}</b>, which alerts on its own "
                f"(threshold {detector.ALERT_THRESHOLD})."),
        section("IP addresses", chips(profile["known_ips"]),
                f"A new IP: <b>+{detector.WEIGHT_NEW_IP}</b>. IPv6 is compared by its /64 network."),
        section(f"Active hours · {hour_range(profile['normal_hours'])}",
                hour_strip(profile["normal_hours"]),
                f"Activity in a grey hour: <b>+{detector.WEIGHT_UNUSUAL_HOUR}</b>."),
        section(f"API calls ({len(profile['known_apis'])})", chips(profile["known_apis"]),
                f"An API not in this list: <b>+{detector.WEIGHT_NEW_API}</b>. A high-risk API adds "
                f"<b>+{detector.WEIGHT_HIGH_RISK_API}</b> (tampering <b>+{detector.WEIGHT_DEFENSE_EVASION}</b>) "
                f"even if it's in the list."),
    ])


def handler(event, context):
    if event.get("describe"):
        return DOCS

    identities = list_identities()
    selected = event.get("identity") or (identities[0] if identities else None)
    profile = detector.fetch_baseline(selected) if selected else None
    return render(identities, selected, profile, context.invoked_function_arn)
