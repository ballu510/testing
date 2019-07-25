import boto3
import json

client = boto3.client('iam')
roleName ='AWS_Created_EMR_Default_Role_Spot_Instances_DO_NOT_DELETE'
policyName = "AWS_Created_EMR_Default_Policy_Spot_Instances_DO_NOT_DELETE"

def createPolicyForEMRDefaultRoleSpotInstance():
# create a policy
    emr_default_policy_spot_instances = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Resource": "*",
            "Action": [
                "cloudwatch:*",
                "cloudformation:CreateStack",
                "cloudformation:DescribeStackEvents",
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:AuthorizeSecurityGroupEgress",
                "ec2:CancelSpotInstanceRequests",
                "ec2:CreateRoute",
                "ec2:CreateSecurityGroup",
                "ec2:CreateTags",
                "ec2:DeleteRoute",
                "ec2:DeleteTags",
                "ec2:DeleteSecurityGroup",
                "ec2:DescribeAvailabilityZones",
                "ec2:DescribeAccountAttributes",
                "ec2:DescribeInstances",
                "ec2:DescribeKeyPairs",
                "ec2:DescribeRouteTables",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeSpotInstanceRequests",
                "ec2:DescribeSpotPriceHistory",
                "ec2:DescribeSubnets",
                "ec2:DescribeVpcAttribute",
                "ec2:DescribeVpcs",
                "ec2:DescribeRouteTables",
                "ec2:DescribeNetworkAcls",
                "ec2:CreateVpcEndpoint",
                "ec2:ModifyImageAttribute",
                "ec2:ModifyInstanceAttribute",
                "ec2:RequestSpotInstances",
                "ec2:RevokeSecurityGroupEgress",
                "ec2:RunInstances",
                "ec2:TerminateInstances",
                "elasticmapreduce:*",
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
                "iam:ListRoles",
                "iam:PassRole",
                "kms:List*",
                "s3:*",
                "sdb:*",
                "application-autoscaling:RegisterScalableTarget",
                "application-autoscaling:DeregisterScalableTarget",
                "application-autoscaling:PutScalingPolicy",
                "application-autoscaling:DeleteScalingPolicy",
                "application-autoscaling:Describe*"
            ]
        },
        {
            "Effect": "Deny",
            "Action": [
                "ec2:RunInstances"
            ],
            "Resource": "arn:aws:ec2:*:*:instance/*",
            "Condition": {
                "StringNotEquals": {
                    "ec2:InstanceMarketType": "spot"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": "iam:CreateServiceLinkedRole",
            "Resource": "arn:aws:iam::*:role/aws-service-role/spot.amazonaws.com/AWSServiceRoleForEC2Spot*",
            "Condition": {
                "StringLike": {
                    "iam:AWSServiceName": "spot.amazonaws.com"
                }
            }
        }
    ]
    }
    try:
        response = client.create_policy(
        PolicyName= policyName,
        PolicyDocument=json.dumps(emr_default_policy_spot_instances)
        )
        #print(response)
        #print(response['Policy']['Arn'])
        policyarn = (response['Policy']['Arn'])
    except client.exceptions.EntityAlreadyExistsException:
        print("Policy already exists")
    except Exception as e:
        print("Unexpected error: %s" % e)
    return policyarn

#Create a role
def createRole():
    path='/'
    description='AWS created default EMR Role for Spot Instances '

    trust_policy={
    "Version": "2012-10-17",
    "Statement": [
        {
        "Sid": "",
        "Effect": "Allow",
        "Principal": {
            "Service": "elasticmapreduce.amazonaws.com"
        },
        "Action": "sts:AssumeRole"
        }
    ]
    }

    tags=[
        {
            'Key': 'Environment',
            'Value': 'Development'
        }
    ]

    try:
        createRole = client.create_role(
            Path=path,
            RoleName=roleName,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description=description,
            MaxSessionDuration=3600,
            Tags=tags
        )
    except client.exceptions.EntityAlreadyExistsException:
        print("Policy already exists")
    except Exception as e:
        print(e)

# Attach policy to the role created earlier.
def attachPolicyToRole():
    try:
        policyarn = createPolicyForEMRDefaultRoleSpotInstance()
        print(policyarn)
        attachPolicy = client.attach_role_policy(
        RoleName= roleName,
        PolicyArn=policyarn
        )
        #print("attachedpolicy")
        #print(attachPolicy)
    except Exception as e:
        print(e)

# List policies
def listPolicies():
    response = client.list_policies(MaxItems=100)
    listPolicies = []
    listPoliciesMarker = []
    for e in response['Policies']:
        listPolicies.append(e['PolicyName'])
        while('Marker' in response):
            response = client.list_policies(MaxItems=100,Marker=response["Marker"])
            for e in response['Policies']:
                listPoliciesMarker.append(e['PolicyName'])
    listPoliciesMarker.extend(listPolicies)
    #print("Policyname in list_policy " + str(listPoliciesMarker))
    return listPoliciesMarker

# List Roles
def listRoles():
    response = client.list_roles(MaxItems=100)
    listRoles = []
    listRolesMarker = []
    for e in response['Roles']:
        listRoles.append(e['RoleName'])
        while('Marker' in response):
            response = client.list_roles(MaxItems=100,Marker=response["Marker"])
            for e in response['Roles']:
                listRolesMarker.append(e['RoleName'])
    listRolesMarker.extend(listRoles)
    return listRolesMarker


def run_me():

    policyNames = listPolicies()
    #print(policyNames)
    if (policyName not in policyNames):
        createPolicyForEMRDefaultRoleSpotInstance()
    else:
        print("Policy already exists")
    roleNames = listRoles()
    #print(roleNames)
    if (roleName not in roleNames):
        createRole()
        attachPolicyToRole()
    else:
        print("Role already exists")

run_me()