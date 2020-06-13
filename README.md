# sysdig-default-policy-loader

## Overview

this script loads Default Sysdig Secure Policy and format for Terraform file


## Usage

1. Get the policy.tf

`SYSDIG_API_KEY=YOUR_APIKEY python mappying_terraform.py > policy.tf`

2. Edit the file as you like

like `vim policy.tf`

3. Apply to your Sysdig account

`terraform apply`

