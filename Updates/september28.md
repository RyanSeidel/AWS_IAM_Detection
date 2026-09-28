Hi guys

I am running terraform and using AWS CLI on my local machine 


Using Powershell to test it 

checking the version to see if it been installed

### Install the tools (Windows, PowerShell — not as Administrator)

    winget install HashiCorp.Terraform
    winget install Amazon.AWSCLI

Close PowerShell and reopen it so PATH refreshes, then check:

    terraform -version     # we are on 1.16
    aws --version


### Get an access key

1. IAM -> Users -> your user -> Security credentials
2. Create access key -> **Command Line Interface (CLI)**
3. The secret shows once only. Do not paste it anywhere.

### Configure and verify

    aws configure
    # key id, secret, us-east-1, json

    aws sts get-caller-identity


I believe this works the same way when cloning AWS on cloudshell 

When running this terraform using terraform apply!!!

PLEASE RUN TERRAFORM DESTROY! when you are no longer using AWS and walking away in order
to save money and to not use any money used. 

