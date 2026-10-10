$k = aws iam create-access-key --user-name dana-test --query AccessKey | ConvertFrom-Json
aws configure set aws_access_key_id     $k.AccessKeyId     --profile dana-test
aws configure set aws_secret_access_key $k.SecretAccessKey --profile dana-test
aws configure set region us-east-1 --profile dana-test
