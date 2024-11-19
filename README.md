# SageMaker Studio - running data science work in network isolation

This sample provides the infrastructure as code in CDK to deploy a SageMaker Studio Domain in VPC-Only mode in private subnets.

## Architecture diagram:

We are deploying the following architecture as described by the figure below

![Architecture Diagram](/image/sm-mlflow-privatelink_2.png)

The CDK stack contains the following resources:

### Networking components
* VPC with private subnets without connectivity to the public internet (no Internet Gateway, no NAT Gateway)
  * 2 private subnets
  * 1 security group

### VPC Endpoints for private connectivity to AWS Services
In order to communicate with the necessary AWS services privately, we are creating VPC Endpoints for the following services:

* Amazon SageMaker Experiments (necessary for interacting with SageMaker Managed MLflow)
* Amazon SageMaker Runtime
* SageMaker APIs
* AWS CodeArtifact API
* AWS CodeArtifact Repositories
* Amazon S3 (Gateway)
* Amazon STS
* Amazon ECR
* Amazon ECR Docker
* Amazon CloudWatch Logs
* Amazon CloudWatch Monitoring
* Amazon EC2

### SageMaker components
* SageMaker Domain in VPCOnly - Asscociated with the VPC created above
* Sagemaker Studio User Profile
* SageMaker Managed MLflow Tracking Server
* AWS CodeArtifact Domain and Repository (linked to the `PyPi` public upstream)
* MLflow Tracking Server
* S3 bucket (host notebook and dataset)
  * S3 bucket policy - read and write granted to **SageMaker Execution Role**, and **MLflow Role**

### Roles and Permissions
* SageMaker Execution Role
  * Managed policy: AmazonSageMakerFullAccess (this policy is ok for a sample, transition to [least privilege](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege) for a production setup)
  * Inline policy: CodeArtifact
  * Inline policy: SageMaker-MLflow
* SageMaker Managed MLflow service role
  * Inline policy:

## CDK Stack deployment

Let us follow these instructions to deploy the stack.

### Prerequisites
* node 18+
* Python 3.10+
* access to an AWS account with `Admin`-like permissions

### Set up the environment

Let's install CDK.
The latest tested version of CDK we used to deploy is `2.162.1`

```Bash
npm install -g aws-cdk@2.162.1
```

From the root of this repository, lets navigate to the `./infra` folder and create a python virtual environment and install the dependencies

```Bash
cd infra
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

By default, this stack will be deployed in the `us-west-2` region.
If you wish to deploy to a different region, please set the ENV variable `AWS_REGION` in your shell to your desired region:
```Bash
export AWS_REGION=<YOUR-DESIRED-REGION>
```

If this is the first time you deploy the AWS CDK stack in an AWS region or your account, you need to [bootstrap](https://docs.aws.amazon.com/cdk/v2/guide/bootstrapping.html) your AWS environment to use AWS CDK.

```
cdk bootstrap aws:/<YOUR-AWS-ACCOUNT-ID>/<YOUR-DESIRED-REGION>
```

Then, from the `infra` folder, run the command to deploy the infrastructure.

```Bash
cdk deploy --require-approval never
```

### Clean up
Before destroying the infrastructure created, make sure you first delete all Spaces and Applications created within the SageMaker Studio Domain (the CDK cannot remove these resources since they might be created outside of the stack itself)

```Bash
cdk destroy
```

## Run the lab

Due to the lack of direct internet connectivity, as part of the Stack creation, we have created and populated a bucket with a notebook to run the lab.
Thanks to the VPC Endpoint to S3, it will be possible for you to download the sample.
As an alternative, you could automate with a LifeCycle Configuration the download of the notebook as part of the initialization of the JupyterLab App.

From the JupyterLab App terminal, run the following command, where `<YOUR-BUCKET-URI>` can be found from the CloudFormation output (either from the terminal, or from the AWS console):

![CDK Output Diagram](/image/cdk-output.png)

```Bash
aws s3 cp --recursive <YOUR-BUCKET-URI> ./
```

Download the reference dataset from [public UC Irvine ML repository](https://archive.ics.uci.edu/ml/machine-learning-databases/00601/ai4i2020.csv) to your local pc, and name it as predictive_maintenance_raw_data_header.csv.
Upload the reference dataset from your local PC to JupyterLab App.

You can now open the `private-mlflow.ipynb` notebook.
