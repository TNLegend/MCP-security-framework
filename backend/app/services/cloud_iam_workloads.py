"""Read-only AWS workload to IAM role identity resolvers.

The operator-selected workload reference is checked in the AWS audit account.
Successful resolution establishes the configured workload's IAM role, but
does not cryptographically attest that the registered MCP process is running
inside that workload. EKS IRSA not proven by a Pod Identity association returns
UNKNOWN; no guessing from a cluster role is permitted.
"""
import re

class IdentityResolutionError(ValueError):
    pass

def resolve_workload(session,account,region,config):
    kind=config["kind"]
    if kind=="EC2":
        item=config["instance_id"]
        response=session.client("ec2",region_name=region).describe_instances(InstanceIds=[item])
        instances=[i for r in response.get("Reservations",[]) for i in r.get("Instances",[])
                   if i.get("InstanceId")==item]
        if len(instances)!=1:
            raise IdentityResolutionError("IAM_WORKLOAD_EC2_NOT_VERIFIED")
        profile=(instances[0].get("IamInstanceProfile") or {}).get("Arn","")
        if ":instance-profile/" not in profile:
            raise IdentityResolutionError("IAM_WORKLOAD_INSTANCE_PROFILE_MISSING")
        name=profile.split(":instance-profile/",1)[-1].rsplit("/",1)[-1]
        data=session.client("iam").get_instance_profile(InstanceProfileName=name)
        roles=data["InstanceProfile"].get("Roles",[])
        if len(roles)!=1 or not roles[0].get("Arn"):
            raise IdentityResolutionError("IAM_WORKLOAD_PROFILE_ROLE_AMBIGUOUS")
        arn=roles[0]["Arn"]
        resource="ec2-instance://"+item
    elif kind=="ECS":
        cluster,task=config["cluster"],config["task"]
        ecs=session.client("ecs",region_name=region)
        response=ecs.describe_tasks(cluster=cluster,tasks=[task])
        tasks=[x for x in response.get("tasks",[]) if
               x.get("taskArn","").split("/")[-1]==task.split("/")[-1]]
        if len(tasks)!=1 or response.get("failures"):
            raise IdentityResolutionError("IAM_WORKLOAD_ECS_TASK_NOT_VERIFIED")
        if tasks[0].get("lastStatus")!="RUNNING":
            raise IdentityResolutionError("IAM_WORKLOAD_ECS_TASK_NOT_RUNNING")
        definition=tasks[0].get("taskDefinitionArn")
        if not definition:
            raise IdentityResolutionError("IAM_WORKLOAD_ECS_DEFINITION_MISSING")
        arn=ecs.describe_task_definition(taskDefinition=definition)["taskDefinition"].get("taskRoleArn")
        resource=tasks[0]["taskArn"]
    elif kind=="LAMBDA":
        function=config["function_name"]
        data=session.client("lambda",region_name=region).get_function_configuration(
            FunctionName=function)
        arn=data.get("Role")
        resource=data.get("FunctionArn") or "lambda-function://"+function
    elif kind=="EKS_POD_IDENTITY":
        client=session.client("eks",region_name=region)
        data=client.describe_pod_identity_association(
            clusterName=config["cluster"],associationId=config["association_id"])
        association=data.get("association") or {}
        if association.get("clusterName") not in (None,config["cluster"]):
            raise IdentityResolutionError("IAM_WORKLOAD_EKS_CLUSTER_MISMATCH")
        if association.get("namespace")!=config["namespace"] or association.get("serviceAccount")!=config["service_account"]:
            raise IdentityResolutionError("IAM_WORKLOAD_EKS_ASSOCIATION_MISMATCH")
        arn=association.get("roleArn")
        # targetRoleArn grants cross-account role chaining, and session policy
        # may narrow authorization. This cannot be treated as a complete
        # effective-authorization verdict.
        if association.get("targetRoleArn"):
            raise IdentityResolutionError("IAM_WORKLOAD_EKS_TARGET_ROLE_CHAIN_UNKNOWN")
        resource="eks-pod-identity://"+config["cluster"]+"/"+config["namespace"]+"/"+config["service_account"]
    else:
        raise IdentityResolutionError("IAM_WORKLOAD_UNSUPPORTED")
    if not isinstance(arn,str) or not re.fullmatch(
        r"arn:aws(?:-us-gov|-cn)?:iam::"+re.escape(account)+r":role/[A-Za-z0-9+=,.@_/-]{1,200}",arn):
        raise IdentityResolutionError("IAM_WORKLOAD_ROLE_ARN_UNVERIFIED")
    return {"role_arn":arn,"workload_type":kind,"resource":resource,
            "role_name":arn.rsplit("/",1)[-1],
            "association":"OPERATOR_SELECTED_WORKLOAD_VERIFIED"}
