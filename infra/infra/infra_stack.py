from aws_cdk import (
    CfnOutput,
    CfnTag,
    RemovalPolicy,
    Stack,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_s3 as s3,
    aws_sagemaker as sagemaker,
    aws_codeartifact as codeartifact,
    aws_s3_deployment as s3_deployment,
    aws_logs as logs
)
from constructs import Construct
import hashlib
from cdk_nag import NagSuppressions

class InfraStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        unique_input = f"{self.account}-{self.region}"
        unique_hash = hashlib.sha256(unique_input.encode('utf-8')).hexdigest()[:10]
        suffix = unique_hash.lower()

        accesslog_bucket_name = f"accesslogs-{suffix}-{self.account}-{self.region}"

        accesslog_bucket = s3.Bucket(
            self,
            "accesslog_bucket",
            versioned=False,
            bucket_name=accesslog_bucket_name,
            public_read_access=False,
            block_public_access= s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
            encryption=s3.BucketEncryption.KMS_MANAGED,
            enforce_ssl=True,
            object_ownership= s3.ObjectOwnership.BUCKET_OWNER_PREFERRED
        )

        sagemaker_bucket = s3.Bucket(
            self,
            'sm-data',
            bucket_name=f"sagemaker-{suffix}-{self.account}-{self.region}",
            auto_delete_objects=True,
            removal_policy=RemovalPolicy.DESTROY,
            block_public_access=s3.BlockPublicAccess(
                block_public_acls=True,
                block_public_policy=True,
                ignore_public_acls=True,
                restrict_public_buckets=True,
            ),
            versioned=False,
            enforce_ssl=True,
            encryption=s3.BucketEncryption.KMS_MANAGED,
            server_access_logs_bucket=accesslog_bucket,
            server_access_logs_prefix=f"mlflow-{suffix}"
        )

        deployment = s3_deployment.BucketDeployment(self, 'notebooks-files',
            sources=[s3_deployment.Source.asset('../notebooks')],
            destination_bucket=sagemaker_bucket
        )

        log_group = logs.LogGroup(self, "MyVpcLogGroup")

        flow_logs_role = iam.Role(
            self, "flowLogsRole",
            assumed_by=iam.ServicePrincipal("vpc-flow-logs.amazonaws.com")
        )

        flow_log_inline_policy = iam.Policy(
            self,
            "flow-log-inline-policy",
            statements=[
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                        "logs:DescribeLogGroups",
                        "logs:DescribeLogStreams"
                    ],
                    resources=["*"],
                    conditions={
                        "StringEquals": {
                            "aws:SourceAccount": self.account
                        },
                        "ArnLike": {
                            "aws:SourceArn": f"arn:aws:ec2:{self.region}:{self.account}:vpc-flow-log/*"
                        }
                    }
                )
            ]
        )
        flow_logs_role.attach_inline_policy(
            flow_log_inline_policy
        )

        # VPC and S3 endpoint
        vpc = ec2.Vpc(
            self,
            'sm-vpc-only',
            ip_addresses=ec2.IpAddresses.cidr('10.10.0.0/16'),
            gateway_endpoints={
                "S3": ec2.GatewayVpcEndpointOptions(
                    service=ec2.GatewayVpcEndpointAwsService.S3
                )
            },
            max_azs=2,
            nat_gateways=0,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    cidr_mask=24,
                    name='sm-private-isolated',
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
                )
            ],
            vpc_name='sm-vpc'
        )

        ec2.FlowLog(
            self, "vpc-flow-logs",
            resource_type=ec2.FlowLogResourceType.from_vpc(vpc),
            destination=ec2.FlowLogDestination.to_cloud_watch_logs(log_group, flow_logs_role),
            traffic_type=ec2.FlowLogTrafficType.ALL,
            max_aggregation_interval=ec2.FlowLogMaxAggregationInterval.TEN_MINUTES,
        )

        # Security group for Studio communication
        studio_security_group = ec2.SecurityGroup(
            self,
            'sm-security-group',
            vpc=vpc,
            description='Studio notebook security group',
            security_group_name='sm-security-group',
            allow_all_outbound=True
        )
        studio_security_group.add_ingress_rule(ec2.Peer.ipv4(vpc.vpc_cidr_block), ec2.Port.tcp(2049), description='NFS between domain and EFS mounts')
        studio_security_group.add_ingress_rule(studio_security_group, ec2.Port.tcp_range(8192, 65535), description='Connectivity between Jupyter Server application and Kernel Gateway applications')
        subnets = [
            vpc.private_subnets[0],
            vpc.private_subnets[1]
        ]

        ## VPC endpoints definitions
        vpc.add_interface_endpoint(
            "sagemaker-api",
            service=ec2.InterfaceVpcEndpointAwsService.SAGEMAKER_API,
            private_dns_enabled=True,
            subnets=ec2.SubnetSelection(subnets=subnets),
            security_groups=[studio_security_group]
        )

        vpc.add_interface_endpoint(
            "sagemaker-runtime",
            service=ec2.InterfaceVpcEndpointAwsService.SAGEMAKER_RUNTIME,
            private_dns_enabled=True,
            subnets=ec2.SubnetSelection(subnets=subnets),
            security_groups=[studio_security_group]
        )

        vpc.add_interface_endpoint(
            "mlflow-experiments",
            service=ec2.InterfaceVpcEndpointAwsService.SAGEMAKER_EXPERIMENTS,
            private_dns_enabled=True,
            subnets=ec2.SubnetSelection(subnets=subnets),
            security_groups=[studio_security_group]
        )

        vpc.add_interface_endpoint(
            "artifact-api",
            service=ec2.InterfaceVpcEndpointAwsService.CODEARTIFACT_API,
            private_dns_enabled=True,
            subnets=ec2.SubnetSelection(subnets=subnets),
            security_groups=[studio_security_group]
        )

        vpc.add_interface_endpoint(
            "artifact-repository",
            service=ec2.InterfaceVpcEndpointAwsService.CODEARTIFACT_REPOSITORIES,
            private_dns_enabled=True,
            subnets=ec2.SubnetSelection(subnets=subnets),
            security_groups=[studio_security_group]
        )

        vpc.add_interface_endpoint(
            "sts",
            service=ec2.InterfaceVpcEndpointAwsService.STS,
            private_dns_enabled=True,
            subnets=ec2.SubnetSelection(subnets=subnets),
            security_groups=[studio_security_group]
        )

        vpc.add_interface_endpoint(
            "s3",
            service=ec2.InterfaceVpcEndpointAwsService.S3,
            private_dns_enabled=True,
            subnets=ec2.SubnetSelection(subnets=subnets),
            security_groups=[studio_security_group]
        )

        vpc.add_interface_endpoint(
            "ecr",
            service=ec2.InterfaceVpcEndpointAwsService.ECR,
            private_dns_enabled=True,
            subnets=ec2.SubnetSelection(subnets=subnets),
            security_groups=[studio_security_group]
        )

        vpc.add_interface_endpoint(
            "ecr-docker",
            service=ec2.InterfaceVpcEndpointAwsService.ECR_DOCKER,
            private_dns_enabled=True,
            subnets=ec2.SubnetSelection(subnets=subnets),
            security_groups=[studio_security_group]
        )

        vpc.add_interface_endpoint(
            "cloudwatch-logs",
            service=ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS,
            private_dns_enabled=True,
            subnets=ec2.SubnetSelection(subnets=subnets),
            security_groups=[studio_security_group]
        )

        vpc.add_interface_endpoint(
            "cloudwatch-monitoring",
            service=ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_MONITORING,
            private_dns_enabled=True,
            subnets=ec2.SubnetSelection(subnets=subnets),
            security_groups=[studio_security_group]
        )

        vpc.add_interface_endpoint(
            "ec2",
            service=ec2.InterfaceVpcEndpointAwsService.EC2,
            private_dns_enabled=True,
            subnets=ec2.SubnetSelection(subnets=subnets),
            security_groups=[studio_security_group]
        )

        # IAM role for SageMaker Studio
        studio_execution_role = iam.Role(
            self,
            'sm-studio-exec-role',
            assumed_by=iam.ServicePrincipal('sagemaker.amazonaws.com'),
            description='SageMaker Studio execution role'
        )
        studio_execution_role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name('AmazonSageMakerFullAccess'))

        mlflow_bucket = s3.Bucket(self, 'sm-mlflow-data',
            bucket_name=f"sagemaker-mlflow-{self.account}-{self.region}",
            auto_delete_objects=True,
            removal_policy=RemovalPolicy.DESTROY,
            block_public_access=s3.BlockPublicAccess(
               block_public_acls=True,
               block_public_policy=True,
               ignore_public_acls=True,
               restrict_public_buckets=True,
            ),
            versioned=False,
            enforce_ssl=True,
            encryption=s3.BucketEncryption.KMS_MANAGED,
            server_access_logs_bucket=accesslog_bucket,
            server_access_logs_prefix=f"mlflow-data-{suffix}"
        )

        mlflow_bucket.add_cors_rule(
            allowed_methods=[
                s3.HttpMethods.GET,
                s3.HttpMethods.PUT,
                s3.HttpMethods.POST,
                s3.HttpMethods.DELETE
            ],
            allowed_origins=['*'],
            allowed_headers=['*']
        )

        mlflow_bucket.grant_read_write(studio_execution_role)

        # SageMaker Studio domain
        studio_domain = sagemaker.CfnDomain(self, 'sm-studio-domain',
            auth_mode='IAM',
            default_user_settings=sagemaker.CfnDomain.UserSettingsProperty(
                execution_role=studio_execution_role.role_arn,
                security_groups=[studio_security_group.security_group_id]
            ),
            domain_name='sm-domain',
            subnet_ids=[
                vpc.private_subnets[0].subnet_id,
                vpc.private_subnets[1].subnet_id
            ],
            domain_settings=sagemaker.CfnDomain.DomainSettingsProperty(
                docker_settings=sagemaker.CfnDomain.DockerSettingsProperty(
                    enable_docker_access="ENABLED",
                    vpc_only_trusted_accounts=[ # see https://docs.aws.amazon.com/sagemaker/latest/dg/notebooks-available-images.html
                        "885854791233",
                        "137914896644",
                        "053634841547",
                        "542918446943",
                        "238384257742",
                        "523751269255",
                        "245090515133",
                        "064688005998",
                        "022667117163",
                        "648430277019",
                        "010972774902",
                        "481561238223",
                        "545423591354",
                        "819792524951",
                        "021081402939",
                        "856416204555",
                        "175620155138",
                        "810671768855",
                        "567556641782",
                        "564864627153"
                    ]
                ),
                security_group_ids=[studio_security_group.security_group_id]
            ),
            vpc_id=vpc.vpc_id,
            app_network_access_type='VpcOnly'
        )

        # SageMaker Studio domain user profile
        studio_domain_user_profile = sagemaker.CfnUserProfile(self, 'sm-studio-domain-user-profile',
            domain_id=studio_domain.attr_domain_id,
            user_profile_name='sm-domain-user'
        )

        codeartifact_domain = codeartifact.CfnDomain(
            self,
            "CodeArtifactDomain",
            domain_name="code-artifact-domain",
        )

        pip_private_codeartifact_repository = codeartifact.CfnRepository(
            self,
            "PipPrivateCodeArtifactRepository",
            domain_name=codeartifact_domain.domain_name,
            repository_name="pip",
            description="Private PyPi repo",
            external_connections=["public:pypi"],
        )

        pip_private_codeartifact_repository.add_depends_on(codeartifact_domain)

        mlflow_role = iam.Role(self, 'mlflow-exec-role',
            assumed_by=iam.ServicePrincipal('sagemaker.amazonaws.com'),
            description='SageMaker MLflow execution role'
        )

        mlflow_bucket.grant_read_write(mlflow_role)

        mlflow_policy = iam.Policy(
            self,
            "mlflow-inline-policy",
            statements=[
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "s3:Get*",
                        "s3:Put*",
                        "s3:List*"
                    ],
                    resources=[
                        f"{mlflow_bucket.bucket_arn}",
                        f"{mlflow_bucket.bucket_arn}/*",
                    ]
                ),
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "sagemaker:AddTags",
                        "sagemaker:CreateModelPackageGroup",
                        "sagemaker:CreateModelPackage",
                        "sagemaker:UpdateModelPackage",
                        "sagemaker:DescribeModelPackageGroup",
                    ],
                    resources=["*"]
                )
            ]
       )

        mlflow_role.attach_inline_policy(
            mlflow_policy
        )

        tracking_server_name = 'mlflow-server'
        tracking_server = sagemaker.CfnMlflowTrackingServer(
            self,
            'mlflow-tracking-server',
            artifact_store_uri=f"s3://{mlflow_bucket.bucket_name}/{tracking_server_name}",
            automatic_model_registration=True,
            mlflow_version='2.13.2',
            tracking_server_name=tracking_server_name,
            role_arn=mlflow_role.role_arn,
            tags=[
                CfnTag(key="domain_id", value=studio_domain.attr_domain_id)
            ]
        )

        mlflow_policy_for_execution_role = iam.Policy(
            self,
            "mlflow_policy_for_execution_role",
            statements=[
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "sagemaker-mlflow:*"
                    ],
                    resources=[tracking_server.attr_tracking_server_arn],
                )
            ]
        )

        codeartifact_policy = iam.Policy(
            self,
            "codeartifacts-policy",
            statements=[
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "codeartifact:*",
                        "sts:GetServiceBearerToken",
                        "sts:GetCallerIdentity"
                    ],
                    resources=["*"]
                ),
                iam.PolicyStatement(
                    effect=iam.Effect.DENY,
                    actions=[
                        "codeartifact:CreateDomain",
                        "codeartifact:CreateRepository",
                        "codeartifact:DeleteDomain",
                        "codeartifact:DeleteDomainPermissionsPolicy",
                        "codeartifact:DeletePackageVersions",
                        "codeartifact:DeleteRepository",
                        "codeartifact:DeleteRepositoryPermissionsPolicy",
                        "codeartifact:PutDomainPermissionsPolicy",
                        "codeartifact:PutRepositoryPermissionsPolicy",
                        "codeartifact:UpdateRepository"
                    ],
                    resources=["*"]
                ),
            ]
        )

        studio_execution_role.attach_inline_policy(
            mlflow_policy_for_execution_role
        )

        studio_execution_role.attach_inline_policy(
            codeartifact_policy
        )

        studio_execution_role.attach_inline_policy(
            mlflow_policy
        )

        NagSuppressions.add_resource_suppressions(
            construct=codeartifact_policy,
            suppressions=[
                {
                    "id": 'AwsSolutions-IAM5',
                    "reason": 'part of an in-line policy which includes ALLOW and DENY'
                }
            ]
        )

        NagSuppressions.add_resource_suppressions(
            construct=mlflow_policy,
            suppressions=[
                {
                    "id": 'AwsSolutions-IAM5',
                    "reason": 'Policy for MLflow service role to write to the bucket model artifacts and write to model registry'
                }
            ]
        )

        NagSuppressions.add_resource_suppressions(
            construct=mlflow_policy_for_execution_role,
            suppressions=[
                {
                    "id": 'AwsSolutions-IAM5',
                    "reason": 'unknown log flow iD',
                    "applies_to": [
                        "Action::sagemaker-mlflow:*"
                    ]
                }
            ]
        )

        NagSuppressions.add_resource_suppressions(
            construct=flow_log_inline_policy,
            suppressions=[
                {
                    "id": 'AwsSolutions-IAM5',
                    "reason": 'Policy taken from the docs https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-iam-role.html'
                }
            ]
        )

        NagSuppressions.add_resource_suppressions(
            construct=sagemaker_bucket,
            suppressions=[
                {
                    "id": "AwsSolutions-S1",
                    "reason": "This bucket does not hold customer data",
                }
            ],
        )

        NagSuppressions.add_resource_suppressions_by_path(
            stack=self,
            path=f"{self.stack_name}/sm-studio-exec-role/DefaultPolicy/Resource",
            suppressions=[
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "This bucket does not hold customer data",
                }
            ],
        )

        NagSuppressions.add_resource_suppressions_by_path(
            stack=self,
            path=f"{self.stack_name}/mlflow-exec-role/DefaultPolicy/Resource",
            suppressions=[
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "This bucket does not hold customer data",
                }
            ],
        )

        NagSuppressions.add_resource_suppressions(
            construct=studio_execution_role,
            suppressions=[
                {
                    "id": 'AwsSolutions-IAM4',
                    "reason": 'Allows SageMakerFullAccess for the sample data for ease of testing',
                    "appliesTo": [
                        'Policy::arn:<AWS::Partition>:iam::aws:policy/AmazonSageMakerFullAccess'
                    ]
                }
            ],
        )

        NagSuppressions.add_resource_suppressions(
            construct=deployment,
            suppressions=[
                {
                    "id": 'AwsSolutions-IAM5',
                    "reason": 'Higher level construct to create a bucket to download the notebook'
                }
            ]
        )

        CfnOutput(self, "Stack ID", value=self.stack_id)
        CfnOutput(self, "VPC ID", value=vpc.vpc_id)
        CfnOutput(self, "Studio Domain ID", value=studio_domain.attr_domain_id)
        CfnOutput(self, "Studio Domain URL", value=studio_domain.attr_url)
        CfnOutput(self, "Studio Domain User Profile", value=studio_domain_user_profile.user_profile_name)
        CfnOutput(self, "Security group ID", value=studio_security_group.security_group_id)
        CfnOutput(self, "Private Subnet 1 ID", value=vpc.private_subnets[0].subnet_id)
        CfnOutput(self, "Private Subnet 2 ID", value=vpc.private_subnets[1].subnet_id)
        CfnOutput(self, "notebook bucket", value=f"s3://{sagemaker_bucket.bucket_name}")
