import json
import os
import boto3

iam_client = boto3.client("iam")
sns_client = boto3.client("sns")

DENY_ALL_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]
}

TOPIC_ARN = os.environ.get("ALERT_TOPIC")

def handler(event, context):
    action = event.get("action", "block")  # "block" or "revoke"
    identity = event.get("identity", "")
    user_type = event.get("user_type", "")
    user_name = event.get("user_name")

    if "root" in identity.lower() or "insider-threat-detector" in identity:
        return {"statusCode": 200, "body": "Skipped: protected identity"}

    actions = []
    try:
        if user_type == "IAMUser" and user_name:
            if action == "block":
                iam_client.put_user_policy(
                    UserName=user_name,
                    PolicyName="InsiderThreat-DenyAll",
                    PolicyDocument=json.dumps(DENY_ALL_POLICY)
                )
                actions.append(f"Attached DenyAll to user {user_name}")

                for key in iam_client.list_access_keys(UserName=user_name).get("AccessKeyMetadata", []):
                    if key["Status"] == "Active":
                        iam_client.update_access_key(
                            UserName=user_name,
                            AccessKeyId=key["AccessKeyId"],
                            Status="Inactive"
                        )
                        actions.append(f"Deactivated key {key['AccessKeyId']}")

            elif action == "revoke":
                try:
                    iam_client.delete_user_policy(
                        UserName=user_name,
                        PolicyName="InsiderThreat-DenyAll"
                    )
                    actions.append(f"Removed DenyAll from user {user_name}")
                except iam_client.exceptions.NoSuchEntityException:
                    actions.append("No DenyAll policy found")

                for key in iam_client.list_access_keys(UserName=user_name).get("AccessKeyMetadata", []):
                    if key["Status"] == "Inactive":
                        iam_client.update_access_key(
                            UserName=user_name,
                            AccessKeyId=key["AccessKeyId"],
                            Status="Active"
                        )
                        actions.append(f"Reactivated key {key['AccessKeyId']}")

        elif user_type == "AssumedRole":
            role_name = identity.split("/")[-1]
            if action == "block":
                iam_client.put_role_policy(
                    RoleName=role_name,
                    PolicyName="InsiderThreat-DenyAll",
                    PolicyDocument=json.dumps(DENY_ALL_POLICY)
                )
                actions.append(f"Attached DenyAll to role {role_name}")
            elif action == "revoke":
                try:
                    iam_client.delete_role_policy(
                        RoleName=role_name,
                        PolicyName="InsiderThreat-DenyAll"
                    )
                    actions.append(f"Removed DenyAll from role {role_name}")
                except iam_client.exceptions.NoSuchEntityException:
                    actions.append("No DenyAll policy found")

        # Send email notification
        if TOPIC_ARN and actions:
            subject = f"[InsiderWatch] Account {action.upper()}ED: {user_name or identity}"
            body = f"Action: {action.upper()}\nIdentity: {identity}\nDetails:\n- " + "\n- ".join(actions)
            sns_client.publish(TopicArn=TOPIC_ARN, Subject=subject[:100], Message=body)

    except Exception as e:
        return {"statusCode": 500, "body": f"Error: {e}"}

    return {"statusCode": 200, "body": json.dumps(actions)}