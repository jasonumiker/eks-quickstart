"""
Purpose

Example of a CodeBuild GitOps pattern where merging a change to the eks_cluster.py will trigger a
CodeBuild to invoke a cdk deploy of that change.

To provide GitHub credentials run:
aws codebuild import-source-credentials --server-type GITHUB --auth-type PERSONAL_ACCESS_TOKEN --token <token_value>
"""

from aws_cdk import (
    aws_iam as iam,
    aws_codebuild as codebuild,
    core,
)
import os

from codebuild_custom_resource import CodeBuildObjectResource

class EKSCodeBuildStack(core.Stack):

    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # Create IAM Role For CodeBuild
        # TODO Make this role's policy least privilege
        aws_app_resources_build_role = iam.Role(
            self, "EKSCodeBuildRole",
            assumed_by=iam.ServicePrincipal("codebuild.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AdministratorAccess")
            ]
        )

        # We only want to fire on the master branch and if there is a change in the dockerbuild folder
        git_hub_source = codebuild.Source.git_hub(
            owner="jasonumiker",
            repo="eks-quickstart",
            webhook=True,
            webhook_filters=[
                codebuild.FilterGroup.in_event_of(codebuild.EventAction.PUSH).and_branch_is("main").and_file_path_is("cluster-bootstrap/*")
            ]
        )

        # Create CodeBuild
        build_project = codebuild.Project(
            self, "EKSCodeBuild",
            source=git_hub_source,
            role=aws_app_resources_build_role,
            environment=codebuild.BuildEnvironment(
                build_image=codebuild.LinuxBuildImage.STANDARD_5_0,
                compute_type=codebuild.ComputeType.LARGE
            ),
            build_spec=codebuild.BuildSpec.from_source_filename("cluster-bootstrap/buildspec.yml")
        )

        """ 
        # This triggers CDK assets and therefore a cdk deploy being required defeating the purpose
        # of this whole thing so going to rethink this one...
        # Kick off our CodeBuild deployment once on the stack deployment (the webhook will take it from there)
        CodeBuildObjectResource(
            self, "CodeBuildObjectResource",
            codebuild_name=build_project.project_name,
            codebuild_arn=build_project.project_arn
        )
        """


app = core.App()
eks_codebuild_stack = EKSCodeBuildStack(app, "EKSCodeBuildStack")
app.synth()