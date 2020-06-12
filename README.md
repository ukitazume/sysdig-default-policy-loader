# sysdig-default-policy-loader

## Overview

this script loads Default Sysdig Secure Policy and format for Terraform file


## Usage

Get the policy.tf

`SYSDIG_API_KEY=YOUR_APIKEY python mappying_terraform.py > policy.tf`

Edit the file as you like

`vim policy.tf

Apply to your Sysdig account

`terraform apply`

