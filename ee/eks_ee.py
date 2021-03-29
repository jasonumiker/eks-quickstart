from aws_cdk import (
    aws_codebuild as codebuild,
    aws_iam as iam,
    aws_codepipeline as codepipeline,
    aws_codepipeline_actions as codepipeline_actions,
    aws_s3 as s3,
    core
)
import os

class EnvironmentStack(core.Stack):

    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # Create IAM Role For CodeBuild
        codebuild_role = iam.Role(
            self, "BuildRole",
            assumed_by=iam.CompositePrincipal(
                iam.ServicePrincipal("codebuild.amazonaws.com")
            ),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AdministratorAccess")
            ]
        )

        instance_profile = iam.CfnInstanceProfile(
            self, "InstanceProfile",
            roles=[codebuild_role.role_name]            
        )

        # Create CodeBuild PipelineProject
        build_project = codebuild.PipelineProject(
            self, "BuildProject",
            role=codebuild_role,
            build_spec=codebuild.BuildSpec.from_source_filename("buildspec.yml"),
            environment=codebuild.BuildEnvironment(
                build_image=codebuild.LinuxBuildImage.STANDARD_5_0,
                compute_type=codebuild.ComputeType.LARGE
            )
        )

        # Create CodePipeline
        pipeline = codepipeline.Pipeline(
            self, "Pipeline",
        )

        # Create Artifact
        artifact = codepipeline.Artifact()

        # S3 Source Bucket
        source_bucket = s3.Bucket.from_bucket_attributes(
            self, "SourceBucket",
            bucket_arn=core.Fn.join("",["arn:aws:s3:::ee-assets-prod-",core.Fn.ref("AWS::Region")])
        )

        # Add Source Stage
        pipeline.add_stage(
            stage_name="Source",
            actions=[
                codepipeline_actions.S3SourceAction(
                    action_name="S3SourceRepo",
                    bucket=source_bucket,
                    bucket_key="modules/c52c7d8ba87d4217a2bf045037b58b5d/v1/source.zip",
                    output=artifact,
                    trigger=codepipeline_actions.S3Trigger.NONE
                )
            ]
        )

        # Add CodeBuild Stage
        pipeline.add_stage(
            stage_name="Deploy",
            actions=[
                codepipeline_actions.CodeBuildAction(
                    action_name="CodeBuildProject",
                    project=build_project,
                    type=codepipeline_actions.CodeBuildActionType.BUILD,
                    input=artifact
                )
            ]
        )

app = core.App()
environment_stack = EnvironmentStack(app, "EnvironmentStack")
app.synth()