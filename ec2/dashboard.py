import streamlit as st
import pandas as pd
import boto3
import datetime
import os
import json
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
from boto3.dynamodb.conditions import Key
from streamlit_cookies_controller import CookieController

# --- PAGE CONFIGURATION ---
st.set_page_config(page_title="InsiderWatch Dashboard", layout="wide", initial_sidebar_state="expanded")

# Initialize the cookie controller
cookie_controller = CookieController()

COGNITO_CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID")
AWS_REGION = "us-east-1" 

# ==========================================
# 1. AUTHENTICATION LOGIC
# ==========================================
def check_password():
    if cookie_controller.get("auth_status") == "logged_in":
        st.session_state["authenticated"] = True
        return True

    if "authenticated" not in st.session_state:
        st.session_state["authenticated"] = False
    if "require_new_password" not in st.session_state:
        st.session_state["require_new_password"] = False

    if st.session_state["authenticated"]:
        return True

    st.markdown("### Insider Threat Dashboard Login")
    client = boto3.client('cognito-idp', region_name=AWS_REGION)

    if st.session_state["require_new_password"]:
        with st.form("new_password_form"):
            st.warning("You must change your temporary password to continue.")
            new_password = st.text_input("New Password:", type="password")
            submit_new = st.form_submit_button("Set Password & Log In")

            if submit_new:
                try:
                    client.respond_to_auth_challenge(
                        ClientId=COGNITO_CLIENT_ID,
                        ChallengeName='NEW_PASSWORD_REQUIRED',
                        Session=st.session_state["auth_session"],
                        ChallengeResponses={
                            'USERNAME': st.session_state["auth_username"],
                            'NEW_PASSWORD': new_password
                        }
                    )
                    st.session_state["authenticated"] = True
                    st.session_state["require_new_password"] = False
                    cookie_controller.set("auth_status", "logged_in", max_age=86400)
                    st.rerun()
                except Exception as e:
                    st.error(f"Error setting new password: {str(e)}")
        return False

    with st.form("login_form"):
        username = st.text_input("Username (Email):")
        password = st.text_input("Password:", type="password")
        submit_button = st.form_submit_button("Log In")

        if submit_button:
            try:
                response = client.initiate_auth(
                    ClientId=COGNITO_CLIENT_ID,
                    AuthFlow='USER_PASSWORD_AUTH',
                    AuthParameters={
                        'USERNAME': username,
                        'PASSWORD': password
                    }
                )
                
                if response.get('ChallengeName') == 'NEW_PASSWORD_REQUIRED':
                    st.session_state["require_new_password"] = True
                    st.session_state["auth_session"] = response['Session']
                    st.session_state["auth_username"] = username
                    st.rerun()
                else:
                    st.session_state["authenticated"] = True
                    cookie_controller.set("auth_status", "logged_in", max_age=86400)
                    st.rerun()
                    
            except Exception as e:
                st.error(f"Login error: {str(e)}")
                
    return False

# Stop execution if not logged in
if not check_password():
    st.stop()


# ==========================================
# 2. SCORING WEIGHTS & CONSTANTS
# ==========================================
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


# ==========================================
# 3. AWS DATA FETCHING
# ==========================================
@st.cache_data(ttl=4)
def load_dynamodb_data(table_name):
    """Fetches all items to allow global profile filtering"""
    try:
        dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
        table = dynamodb.Table(table_name)
        response = table.scan()
        data = response.get('Items', [])
        while 'LastEvaluatedKey' in response:
            response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
            data.extend(response.get('Items', []))
        return data
    except Exception as e:
        st.error(f"Error loading data from {table_name}: {e}")
        return []

all_alerts = load_dynamodb_data('insider-threat-alerts')
all_baselines = load_dynamodb_data('insider-threat-baseline')


# ==========================================
# 4. SIDEBAR NAVIGATION & GLOBAL FILTER
# ==========================================
st.sidebar.title("🛡️ InsiderWatch")
st.sidebar.caption("AWS IAM Insider Threat Detection")
st.sidebar.divider()

# Extract unique identities for the dropdown
profiles = set()
for item in all_alerts + all_baselines:
    if 'identity' in item:
        profiles.add(item['identity'])
unique_profiles = sorted(list(profiles))

st.sidebar.markdown("**Select AWS Identity to Inspect:**")
selected_identity = st.sidebar.selectbox(
    "Identity",
    options=["All Profiles"] + unique_profiles,
    label_visibility="collapsed",
    key="identity_selector"
)

st.sidebar.divider()
page = st.sidebar.radio("Navigation", ["My alerts", "What's normal for me", "What triggers an alert"])

# Filter data based on dropdown
if selected_identity == "All Profiles":
    filtered_alerts = all_alerts
    filtered_baseline_item = None # Cannot show a single baseline for "All Profiles"
else:
    filtered_alerts = [item for item in all_alerts if item.get('identity') == selected_identity]
    baselines = [item for item in all_baselines if item.get('identity') == selected_identity and item.get('facet') == 'profile']
    filtered_baseline_item = baselines[0] if baselines else None

# Sort alerts by sort key (time) descending
filtered_alerts.sort(key=lambda x: x.get('sk', ''), reverse=True)


# ==========================================
# 5. PAGE 1: MY ALERTS (OPTIMIZED FRAGMENT)
# ==========================================
if page == "My alerts":
    # --- 1. STATIC UI (Outside Fragment: Only loads once) ---
    st.header("My alerts")
    
    if selected_identity == "All Profiles":
        st.markdown("Showing events for **ALL Profiles**. Red is ≥ 75 (Emailed Alert).")
    else:
        st.markdown(f"Events scored for `{selected_identity.split('/')[-1]}`. **Red is ≥ 75 (Emailed Alert)**.")
        
    show_all = st.checkbox("Show events below 75 (Normal activity)", value=False)
    
    # --- 2. DYNAMIC UI (Inside Fragment: Refreshes every 5 seconds) ---
    @st.fragment(run_every=5)
    def display_alerts_table():
        fresh_alerts = load_dynamodb_data('insider-threat-alerts')
        
        if selected_identity == "All Profiles":
            current_alerts = fresh_alerts
        else:
            current_alerts = [item for item in fresh_alerts if item.get('identity') == selected_identity]
            
        current_alerts.sort(key=lambda x: x.get('sk', ''), reverse=True)
        
        if not current_alerts:
            st.info("No events found in the alerts table for the selected identity.")
            return

        formatted_data = []
        for item in current_alerts:
            time_utc = item.get("sk", "").split("#")[0]
            tactics = item.get("tactics", [])
            formatted_data.append({
                "IDENTITY": item.get("identity", "Unknown").split('/')[-1],
                "TIME (UTC)": time_utc, 
                "API CALL": item.get("api", "Unknown"),
                "REGION": item.get("region", "Unknown"), 
                "SOURCE IP": item.get("source_ip", "Unknown"),
                "SCORE": int(item.get("score", 0)), 
                "TACTIC": ", ".join(tactics) if tactics else "N/A",
                "_raw_item": item
            })
            
        df = pd.DataFrame(formatted_data)
        
        if selected_identity != "All Profiles":
            df = df.drop(columns=["IDENTITY"])
            
        # Reads the checkbox value from the static UI above
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
            st.dataframe(styled_df, use_container_width=True, hide_index=True)
            
            st.divider()
            st.subheader("Alert Detail View")
            
            alert_options = display_df.apply(lambda x: f"{x['TIME (UTC)']} | {x['API CALL']} (Score: {x['SCORE']})", axis=1).tolist()
            
            # Explicit key added here to prevent losing focus during background refreshes
            selected_alert_str = st.selectbox("Select an event to inspect:", alert_options, key="alert_detail_dropdown")
            
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
            # --- PREVENTION BUTTONS ---
            if score >= ALERT_THRESHOLD:
                st.divider()
                st.subheader("Prevention Actions")
                
                identity_arn = selected_raw_item.get("identity", "")
                user_type = "IAMUser" if ":user/" in identity_arn else "AssumedRole"
                user_name = identity_arn.split("/")[-1] if user_type == "IAMUser" else None
                sk = selected_raw_item.get("sk")

                col_block, col_revoke = st.columns(2)

                # Block confirmation
                with col_block:
                    if st.session_state.get(f"confirm_block_{sk}") != True:
                        if st.button("Block this identity", type="primary", key=f"block_{sk}"):
                            st.session_state[f"confirm_block_{sk}"] = True
                            st.rerun()
                    else:
                        st.warning("Are you sure you want to BLOCK this identity?")
                        c1, c2 = st.columns(2)
                        with c1:
                            if st.button("Yes, Block", key=f"yes_block_{sk}"):
                                try:
                                    lambda_client = boto3.client("lambda", region_name=AWS_REGION)
                                    payload = {
                                        "action": "block",
                                        "identity": identity_arn,
                                        "user_type": user_type,
                                        "user_name": user_name
                                    }
                                    response = lambda_client.invoke(
                                        FunctionName="insider-threat-quarantine",
                                        InvocationType="RequestResponse",
                                        Payload=json.dumps(payload)
                                    )
                                    result = json.loads(response["Payload"].read().decode())
                                    st.session_state[f"result_{sk}"] = ("success", f"Blocked successfully: {result}")
                                except Exception as e:
                                    st.session_state[f"result_{sk}"] = ("error", f"Failed to block: {e}")
                                st.session_state[f"confirm_block_{sk}"] = False
                                st.rerun(scope="fragment")
                        with c2:
                            if st.button("Cancel", key=f"cancel_block_{sk}"):
                                st.session_state[f"confirm_block_{sk}"] = False
                                st.rerun()

                # Revoke confirmation
                with col_revoke:
                    if st.session_state.get(f"confirm_revoke_{sk}") != True:
                        if st.button("Revoke / Unblock", key=f"revoke_{sk}"):
                            st.session_state[f"confirm_revoke_{sk}"] = True
                            st.rerun()
                    else:
                        st.warning("Are you sure you want to REVOKE (unblock) this identity?")
                        c1, c2 = st.columns(2)
                        with c1:
                            if st.button("Yes, Revoke", key=f"yes_revoke_{sk}"):
                                try:
                                    lambda_client = boto3.client("lambda", region_name=AWS_REGION)
                                    payload = {
                                        "action": "revoke",
                                        "identity": identity_arn,
                                        "user_type": user_type,
                                        "user_name": user_name
                                    }
                                    response = lambda_client.invoke(
                                        FunctionName="insider-threat-quarantine",
                                        InvocationType="RequestResponse",
                                        Payload=json.dumps(payload)
                                    )
                                    result = json.loads(response["Payload"].read().decode())
                                    st.session_state[f"result_{sk}"] = ("success", f"Revoked successfully: {result}")
                                except Exception as e:
                                    st.session_state[f"result_{sk}"] = ("error", f"Failed to revoke: {e}")
                                st.session_state[f"confirm_revoke_{sk}"] = False
                                st.rerun(scope="fragment")
                        with c2:
                            if st.button("❌ Cancel", key=f"cancel_revoke_{sk}"):
                                st.session_state[f"confirm_revoke_{sk}"] = False
                                st.rerun()

                # Show the last action result (persists across auto-refreshes)
                if f"result_{sk}" in st.session_state:
                    kind, msg = st.session_state[f"result_{sk}"]
                    (st.success if kind == "success" else st.error)(msg)
            else:
                st.caption(f"Prevention actions are available for events scoring {ALERT_THRESHOLD} or higher.")
    # Execute the fragment
    display_alerts_table()

# ==========================================
# 6. PAGE 2: WHAT'S NORMAL FOR ME (ORIGINAL UI)
# ==========================================
elif page == "What's normal for me":
    st.header("What's normal for me")
    
    if selected_identity == "All Profiles":
        st.warning("Please select a specific AWS Identity from the sidebar to view its baseline profile.")
    elif not filtered_baseline_item:
        st.warning(f"No baseline data found for `{selected_identity}`. Please run the seed_baseline.py script.")
    else:
        st.markdown(f"Your Behavioral Baseline Profile for `{selected_identity.split('/')[-1]}`")
        col1, col2 = st.columns(2)
        with col1:
            with st.container(border=True):
                st.subheader("Regions you use")
                regions = filtered_baseline_item.get("regions", [])
                st.code("\n".join(regions) if regions else "None")
                st.caption("Any other region: **+75 points**.")
                
            with st.container(border=True):
                st.subheader("IP addresses you use")
                ips = filtered_baseline_item.get("source_ips", [])
                st.code("\n".join(ips) if ips else "None")
                st.caption("A new IP: **+25 points**.")

        with col2:
            with st.container(border=True):
                st.subheader("Hours you're active (UTC)")
                hours = sorted([int(h) for h in filtered_baseline_item.get("hours", [])])
                hour_str = ", ".join([str(h) for h in hours]) if hours else "None"
                st.markdown(f"`{hour_str}`")
                st.caption("Activity outside these hours: **+25 points**.")

        with st.container(border=True):
            st.subheader(f"API calls you've made ({len(filtered_baseline_item.get('apis', []))})")
            apis = filtered_baseline_item.get("apis", [])
            cols = st.columns(4)
            for i, api in enumerate(apis):
                cols[i % 4].code(api)
            st.caption("An API not in this list: **+20 points**.")


# ==========================================
# 7. PAGE 3: WHAT TRIGGERS AN ALERT (ORIGINAL UI)
# ==========================================
elif page == "What triggers an alert":
    st.header("What triggers an alert")
    
    if selected_identity == "All Profiles":
        st.warning("Please select a specific AWS Identity from the sidebar to test its baseline.")
    else:
        st.markdown(f"Predict alert scores by testing API calls against the live baseline for `{selected_identity.split('/')[-1]}`.")
        
        col_sim, col_matrix = st.columns([1.2, 1])
        
        with col_sim:
            st.subheader("What-if Calculator")
            
            known_regions = filtered_baseline_item.get('regions', []) if filtered_baseline_item else []
            known_ips = filtered_baseline_item.get('source_ips', []) if filtered_baseline_item else []
            known_hours = [int(h) for h in filtered_baseline_item.get('hours', [])] if filtered_baseline_item else []
            
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
                    
                    if not filtered_baseline_item:
                        score += 40
                        reasons.append("+40 Identity has no baseline profile")
                    
                    if api_call in HIGH_RISK_APIS:
                        score += WEIGHT_HIGH_RISK_API
                        reasons.append(f"+40 High-risk API ({HIGH_RISK_APIS[api_call]})")
                        if api_call == "cloudtrail:StopLogging":
                            score += 35 
                            reasons.append("+35 Detector Tampering/Defense Evasion")
                    
                    if filtered_baseline_item:
                        if api_call not in filtered_baseline_item.get('apis', []):
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