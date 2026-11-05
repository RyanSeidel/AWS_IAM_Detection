import streamlit as st
import pandas as pd
import boto3
import datetime
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
from boto3.dynamodb.conditions import Key

# --- PAGE CONFIGURATION ---
st.set_page_config(page_title="InsiderWatch Dashboard", layout="wide", initial_sidebar_state="expanded")

# --- SCORING WEIGHTS (From handler.py) ---
ALERT_THRESHOLD = 75
WEIGHT_NEW_REGION = 75
WEIGHT_NEW_API = 20
WEIGHT_UNUSUAL_HOUR = 25
WEIGHT_NEW_IP = 25
WEIGHT_HIGH_RISK_API = 40
WEIGHT_ACCESS_DENIED = 25
WEIGHT_DEFENSE_EVASION = 75

HIGH_RISK_APIS = {
    "iam:CreateAccessKey": "Persistence", "iam:CreateUser": "Persistence",
    "ssm:GetParameter": "Credential Access", "ec2:RunInstances": "Resource Hijacking",
    "cloudtrail:StopLogging": "Defense Evasion"
}

# --- AWS DATA FETCHING ---
@st.cache_data(ttl=3600)
def get_aws_identity():
    try:
        sts = boto3.client('sts')
        return sts.get_caller_identity()['Arn']
    except Exception:
        return "arn:aws:iam::123456789012:user/dana-test (Mocked)"

current_identity = get_aws_identity()
dynamodb = boto3.resource('dynamodb')

@st.cache_data(ttl=10)
def fetch_my_alerts(identity):
    try:
        table = dynamodb.Table('insider-threat-alerts')
        response = table.query(KeyConditionExpression=Key('identity').eq(identity))
        items = response.get('Items', [])
        items.sort(key=lambda x: x['sk'], reverse=True)
        return items
    except Exception as e:
        st.error(f"Failed to fetch alerts: {e}")
        return []

@st.cache_data(ttl=60)
def fetch_my_baseline(identity):
    try:
        table = dynamodb.Table('insider-threat-baseline')
        response = table.query(KeyConditionExpression=Key('identity').eq(identity) & Key('facet').eq('profile'))
        items = response.get('Items', [])
        return items[0] if items else None
    except Exception as e:
        st.error(f"Failed to fetch baseline: {e}")
        return None

baseline_data = fetch_my_baseline(current_identity)

# --- SIDEBAR NAVIGATION ---
st.sidebar.title("🛡️ InsiderWatch")
st.sidebar.caption("AWS IAM Insider Threat Detection")
st.sidebar.divider()
st.sidebar.markdown("**Active AWS Identity:**")
st.sidebar.code(current_identity, language="text")
st.sidebar.divider()

page = st.sidebar.radio("Navigation", ["My alerts", "What's normal for me", "What triggers an alert"])

# --- PAGE 1: MY ALERTS ---
if page == "My alerts":
    st.header("My alerts")
    st.markdown("Events scored by the detection engine. **Red is ≥ 75 (Emailed Alert)**.")
    
    show_all = st.checkbox("Show events below 75 (Normal activity)", value=False)
    raw_alerts = fetch_my_alerts(current_identity)
    
    if not raw_alerts:
        st.info("No events found in the alerts table for your identity.")
    else:
        formatted_data = []
        for item in raw_alerts:
            time_utc = item.get("sk", "").split("#")[0]
            tactics = item.get("tactics", [])
            formatted_data.append({
                "TIME (UTC)": time_utc, "API CALL": item.get("api", "Unknown"),
                "REGION": item.get("region", "Unknown"), "SOURCE IP": item.get("source_ip", "Unknown"),
                "SCORE": int(item.get("score", 0)), "TACTIC": ", ".join(tactics) if tactics else "N/A",
                "_raw_item": item
            })
            
        df = pd.DataFrame(formatted_data)
        display_df = df if show_all else df[df["SCORE"] >= 75]
        
        if display_df.empty:
            st.info("No high-risk alerts found. Check the box above to see normal events.")
        else:
            def highlight_scores(row):
                score = row['SCORE']
                if score >= 75: color = '#ffcccc'
                elif score >= 40: color = '#ffe6cc'
                else: color = '#e6f2ff'
                return [f'background-color: {color}; color: black'] * len(row)

            styled_df = display_df.drop(columns=["_raw_item"]).style.apply(highlight_scores, axis=1)
            st.dataframe(styled_df, width='stretch', hide_index=True)
            
            st.divider()
            st.subheader("Alert Detail View")
            alert_options = display_df.apply(lambda x: f"{x['TIME (UTC)']} | {x['API CALL']} (Score: {x['SCORE']})", axis=1).tolist()
            selected_alert_str = st.selectbox("Select an event to inspect:", alert_options)
            
            selected_index = alert_options.index(selected_alert_str)
            selected_raw_item = display_df.iloc[selected_index]["_raw_item"]
            
            score = int(selected_raw_item.get('score', 0))
            api_call = selected_raw_item.get('api', 'Unknown')
            emailed_badge = " - EMAILED" if score >= 75 else ""
            
            if score >= 75: st.error(f"**{api_call} | Score: {score}{emailed_badge}**")
            else: st.info(f"**{api_call} | Score: {score}**")
                
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("**WHY IT SCORED**")
                for reason in selected_raw_item.get("reasons", []):
                    st.markdown(f"* {reason}")
            with col2:
                tactics = selected_raw_item.get('tactics', [])
                st.markdown(f"**MITRE Tactic:** {', '.join(tactics) if tactics else 'N/A'}")
                if score >= 75:
                    st.warning("This event crossed the 75-point threshold and triggered an email.")
                    with st.expander("View Raw SNS Email Body"):
                        st.code(selected_raw_item.get("email_body", "Email body not recorded."), language="text")

# --- PAGE 2: WHAT'S NORMAL FOR ME ---
elif page == "What's normal for me":
    st.header("What's normal for me")
    st.markdown(f"Your Behavioral Baseline Profile for `{current_identity.split('/')[-1]}`")
    
    if not baseline_data:
        st.warning("No baseline data found. Please run the seed_baseline.py script.")
    else:
        col1, col2 = st.columns(2)
        with col1:
            with st.container(border=True):
                st.subheader("Regions you use")
                regions = baseline_data.get("regions", [])
                st.code("\n".join(regions) if regions else "None")
                st.caption("Any other region: **+75 points**.")
                
            with st.container(border=True):
                st.subheader("IP addresses you use")
                ips = baseline_data.get("source_ips", [])
                st.code("\n".join(ips) if ips else "None")
                st.caption("A new IP: **+25 points**.")

        with col2:
            with st.container(border=True):
                st.subheader("Hours you're active (UTC)")
                hours = sorted([int(h) for h in baseline_data.get("hours", [])])
                hour_str = ", ".join([str(h) for h in hours]) if hours else "None"
                st.markdown(f"`{hour_str}`")
                st.caption("Activity outside these hours: **+25 points**.")

        with st.container(border=True):
            st.subheader(f"API calls you've made ({len(baseline_data.get('apis', []))})")
            apis = baseline_data.get("apis", [])
            cols = st.columns(4)
            for i, api in enumerate(apis):
                cols[i % 4].code(api)
            st.caption("An API not in this list: **+20 points**.")

# --- PAGE 3: WHAT TRIGGERS AN ALERT ---
elif page == "What triggers an alert":
    st.header("What triggers an alert")
    st.markdown("Predict alert scores by testing API calls against your live baseline.")
    
    col_sim, col_matrix = st.columns([1.2, 1])
    
    with col_sim:
        st.subheader("What-if Calculator")
        
        # Build dynamic dropdown options based on live baseline
        known_regions = baseline_data.get('regions', []) if baseline_data else []
        known_ips = baseline_data.get('source_ips', []) if baseline_data else []
        known_hours = [int(h) for h in baseline_data.get('hours', [])] if baseline_data else []
        
        with st.form("simulator_form"):
            api_call = st.selectbox("API Call", ["iam:CreateUser", "ssm:GetParameter", "s3:PutObject", "ec2:RunInstances", "cloudtrail:StopLogging", "s3:CreateBucket"])
            region_input = st.text_input("AWS Region", value=known_regions[0] if known_regions else "us-east-1")
            hour_input = st.number_input("Hour (UTC)", min_value=0, max_value=23, value=known_hours[0] if known_hours else 12)
            ip_input = st.text_input("Source IP", value=known_ips[0] if known_ips else "203.0.113.24")
            
            force_deny = st.checkbox("Call denied (AccessDenied)?")
            no_mfa = st.checkbox("Console login without MFA? (Only applies to signin:ConsoleLogin)")
            
            submitted = st.form_submit_button("Calculate Potential Risk Score", type="primary")
            
            if submitted:
                score = 0
                reasons = []
                
                # Missing baseline penalty
                if not baseline_data:
                    score += 40
                    reasons.append("+40 Identity has no baseline profile")
                
                # High Risk API evaluation
                if api_call in HIGH_RISK_APIS:
                    score += WEIGHT_HIGH_RISK_API
                    reasons.append(f"+40 High-risk API ({HIGH_RISK_APIS[api_call]})")
                    if api_call == "cloudtrail:StopLogging":
                        score += 35 
                        reasons.append("+35 Detector Tampering/Defense Evasion")
                
                # Baseline comparisons
                if baseline_data:
                    if api_call not in baseline_data.get('apis', []):
                        score += WEIGHT_NEW_API
                        reasons.append("+20 First time calling this API")
                    if region_input not in known_regions:
                        score += WEIGHT_NEW_REGION
                        reasons.append(f"+75 Uncharacteristic Region ({region_input})")
                    if hour_input not in known_hours:
                        score += WEIGHT_UNUSUAL_HOUR
                        reasons.append(f"+25 Outside normal hours ({hour_input} UTC)")
                    if ip_input not in known_ips:
                        score += WEIGHT_NEW_IP
                        reasons.append(f"+25 New source IP ({ip_input})")
                
                if force_deny:
                    score += WEIGHT_ACCESS_DENIED
                    reasons.append("+25 Call denied (AccessDenied)")
                if no_mfa and api_call == "signin:ConsoleLogin":
                    score += 40
                    reasons.append("+40 Console login without MFA")
                
                st.divider()
                if score >= 75:
                    st.error(f"### 🚨 PREDICTED SCORE: {score}\n**WOULD TRIGGER ALERT!** (Threshold is 75)")
                else:
                    st.success(f"### ✅ PREDICTED SCORE: {score}\n**NO ALERT.** (Threshold is 75)")
                
                for r in reasons:
                    st.markdown(f"- {r}")

    with col_matrix:
        st.subheader("Detection Matrix")
        with st.expander("High-Risk Categories & Point Values", expanded=True):
            st.markdown("""
            * **Tampering (+75):** Stopping CloudTrail, deleting rules.
            * **High-Risk API (+40):** Modifying IAM, reading secrets.
            * **Unknown Identity (+40):** No behavioral baseline exists.
            * **Console w/o MFA (+40):** Root or IAM login lacking MFA.
            * **0.0.0.0/0 Security Group (+35):** Opening resources to the world.
            * **New Region (+75):** Accessing infrastructure outside the baseline.
            * **New IP Address (+25):** Requests from unbaselined subnets.
            * **New API Call (+20):** Accessing an AWS service for the first time.
            * **Access Denied (+25):** Failing authentication or authorization.
            """)