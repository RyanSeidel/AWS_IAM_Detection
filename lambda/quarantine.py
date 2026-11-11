import json
import os
import boto3

iam_client = boto3.client("iam")

DENY_ALL_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]
}

def handler(event, context):
    # Expects: {"identity": "arn:...", "user_type": "IAMUser", "user_name": "alice"}
    identity = event.get("identity", "")
    user_type = event.get("user_type", "")
    user_name = event.get("user_name")

    actions = []

    if "root" in identity.lower() or "insider-threat-detector" in identity:
        return {"statusCode": 200, "body": "Skipped: protected identity"}

    try:
        if user_type == "IAMUser" and user_name:
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

        elif user_type == "AssumedRole":
            role_name = identity.split("/")[-1]
            iam_client.put_role_policy(
                RoleName=role_name,
                PolicyName="InsiderThreat-DenyAll",
                PolicyDocument=json.dumps(DENY_ALL_POLICY)
            )
            actions.append(f"Attached DenyAll to role {role_name}")

    except Exception as e:
        return {"statusCode": 500, "body": f"Error: {e}"}

    return {"statusCode": 200, "body": json.dumps(actions)}