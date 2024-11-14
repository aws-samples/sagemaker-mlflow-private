#!/usr/bin/env python3
import os
import boto3

import aws_cdk as cdk
from infra.infra_stack import InfraStack
import cdk_nag as nag

account_id = boto3.client('sts').get_caller_identity().get('Account')
region = os.getenv('AWS_REGION', 'us-west-2')

app = cdk.App()
infra = InfraStack(app, "SageMakerVCPOnlyMLflow",
    env=cdk.Environment(account=account_id, region=region)
)

cdk.Aspects.of(app).add(nag.AwsSolutionsChecks(verbose=True))


app.synth()