
# Merging all personas and real history together including Danas
python helpers/seed_baseline.py --personas --merge-cloudtrail


cd main
terraform apply -var="demo_user=true"
cd ..


$k = aws iam create-access-key --user-name dana-test --query AccessKey | ConvertFrom-Json
aws configure set aws_access_key_id     $k.AccessKeyId     --profile dana-test
aws configure set aws_secret_access_key $k.SecretAccessKey --profile dana-test
aws configure set region us-east-1 --profile dana-test

aws sts get-caller-identity --profile dana-test
# ✅ ends in :user/dana-test

aws events disable-rule --name insider-threat-risky-calls --region us-east-1 --profile dana-test
# ✅ AccessDeniedException


$key = '{"identity":{"S":"arn:aws:iam::021158484652:user/dana-test"},"facet":{"S":"profile"}}'
[IO.File]::WriteAllText("$PWD\key.json", $key, (New-Object System.Text.UTF8Encoding($false)))
aws dynamodb get-item --table-name insider-threat-baseline --key file://key.json
Remove-Item key.json

aws logs tail /aws/lambda/insider-threat-detector --since 10m --filter-pattern "dana-test"

cd main
terraform apply -var="demo_user=false"   # removes dana, her policy and the fake secret (force_destroy deletes her key too)
cd ..
aws configure set aws_access_key_id "" --profile dana-test   # wipe the local profile
aws configure set aws_secret_access_key "" --profile dana-test




