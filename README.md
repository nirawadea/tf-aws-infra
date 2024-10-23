# tf-aws-infra
# Setting Up AWS Infrastructure with Terraform

## Introduction of terraform

This guide provides comprehensive steps for setting up infrastructure on AWS using Terraform.

## Prerequisites

Before proceeding, ensure you have the following:


- AWS account
- AWS CLI installed
- Terraform CLI installed

Initialize Terraform:
   ```bash
   terraform init
   ```

Validate the configuration:
   ```bash
   terraform validate
   ```

Plan infrastructure changes:
   ```bash
   terraform plan
   ```

Apply the changes to create VPC and subnets:
   ```bash
   terraform apply
   ```

### Checking State

Check the state of your infrastructure using:
```bash
terraform show