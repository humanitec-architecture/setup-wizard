package cloud

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/logging"
	"github.com/google/uuid"
	"github.com/humanitec/humanitec-go-autogen/client"
	v1 "k8s.io/api/core/v1"
	k8s_rbac "k8s.io/api/rbac/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	k8s_meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"

	"github.com/humanitec/humctl-wizard/internal/cluster"
	"github.com/humanitec/humctl-wizard/internal/message"
	"github.com/humanitec/humctl-wizard/internal/platform"
	"github.com/humanitec/humctl-wizard/internal/session"
	"github.com/humanitec/humctl-wizard/internal/utils"

	"sigs.k8s.io/aws-iam-authenticator/pkg/token"
)

type awsProvider struct {
	awsConfig         aws.Config
	humanitecPlatform *platform.HumanitecPlatform
	k8sClient         *kubernetes.Clientset
}

var humanitecOperatorServiceAccount = "humanitec-operator-controller-manager"

type awsLogger struct{}

func (a awsLogger) Logf(classification logging.Classification, format string, v ...interface{}) {
	if classification == logging.Debug {
		message.Debug("AWS SDK: "+format, v...)
	} else {
		message.Warning("AWS SDK: "+format, v...)
	}
}

func newAwsProvider(ctx context.Context, humanitecPlatform *platform.HumanitecPlatform) (Provider, error) {
	var logger awsLogger
	config, err := config.LoadDefaultConfig(ctx,
		config.WithLogConfigurationWarnings(true),
		config.WithLogger(logger),
		config.WithRetryer(func() aws.Retryer {
			return retry.AddWithMaxAttempts(retry.NewStandard(), 5)
		}))
	if err != nil {
		return nil, fmt.Errorf("failed to load aws default configuration, %w", err)
	}

	return &awsProvider{
		awsConfig:         config,
		humanitecPlatform: humanitecPlatform,
	}, nil
}

func (a *awsProvider) GetCallingUserId(ctx context.Context) (string, error) {
	stsClient := sts.NewFromConfig(a.awsConfig)
	caller, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("failed to get caller identity, %w", err)
	}
	if caller == nil || caller.UserId == nil {
		return "", fmt.Errorf("failed to get caller identity: caller or caller.UserId is nil")
	}
	return *caller.UserId, nil
}

func (a *awsProvider) SetupProvider(ctx context.Context) error {
	return nil
}

func (a *awsProvider) CreateCloudIdentity(ctx context.Context, humanitecCloudAccountId, humanitecCloudAccountName string) (string, error) {
	iamClient := iam.NewFromConfig(a.awsConfig)

	if session.State.AwsProvider.CreateCloudIdentity.RoleName != "" {
		isRoleExists, err := a.isRoleExists(ctx, session.State.AwsProvider.CreateCloudIdentity.RoleName)
		if err != nil {
			return "", fmt.Errorf("failed to check if role exists, %w", err)
		}
		if !isRoleExists {
			message.Debug("AWS Role not found: %s, clearing state", session.State.AwsProvider.CreateCloudIdentity.RoleName)
			session.State.AwsProvider.CreateCloudIdentity.RoleName = ""
		}
	}

	if session.State.AwsProvider.CreateCloudIdentity.RoleName == "" {
		externalId := uuid.New().String()
		roleName := generateAwsRoleName("humanitec-access-tempcreds")
		roleDescription := "Role to allow humanitec to assume role"

		trustPolicy := fmt.Sprintf(`{
			"Version": "2012-10-17",
			"Statement": [
				{
				"Effect": "Allow",
				"Principal": {
					"AWS": "arn:aws:iam::767398028804:user/humanitec"
				},
				"Action": "sts:AssumeRole",
				"Condition": {
					"StringEquals": {
					"sts:ExternalId": "%s"
					}
				}
				}
			]
		}`, externalId)

		minifiedTrustPolicy := &bytes.Buffer{}
		if err := json.Compact(minifiedTrustPolicy, []byte(trustPolicy)); err != nil {
			return "", fmt.Errorf("failed to minify trust policy, %w", err)
		}

		message.Info("Creating AWS Role: aws iam create-role --role-name %s --assume-role-policy-document '%s'", roleName, minifiedTrustPolicy.String())
		createRoleResp, err := iamClient.CreateRole(ctx, &iam.CreateRoleInput{
			AssumeRolePolicyDocument: &trustPolicy,
			RoleName:                 &roleName,
			Description:              &roleDescription,
		})
		if err != nil {
			return "", fmt.Errorf("failed to create role, %w", err)
		}

		if createRoleResp == nil || createRoleResp.Role == nil || createRoleResp.Role.Arn == nil || createRoleResp.Role.RoleName == nil {
			return "", fmt.Errorf("failed to create role: createRoleResp, createRoleResp.Role, createRoleResp.Role.Arn or createRoleResp.Role.RoleName is nil")
		}
		session.State.AwsProvider.CreateCloudIdentity.ExternalId = externalId
		session.State.AwsProvider.CreateCloudIdentity.RoleArn = *createRoleResp.Role.Arn
		session.State.AwsProvider.CreateCloudIdentity.RoleName = *createRoleResp.Role.RoleName
		if err := session.Save(); err != nil {
			return "", fmt.Errorf("failed to save state: %w", err)
		}
		message.Info("AWS Role created: %s", *createRoleResp.Role.RoleName)
	} else {
		message.Info("AWS Role already created, loading from state: %s", session.State.AwsProvider.CreateCloudIdentity.RoleName)
	}

	if session.State.AwsProvider.CreateCloudIdentity.HumanitecCloudAccountId != "" {
		getCloudAccountResp, err := a.humanitecPlatform.Client.GetResourceAccountWithResponse(ctx, a.humanitecPlatform.OrganizationId, session.State.AwsProvider.CreateCloudIdentity.HumanitecCloudAccountId)
		if err != nil {
			return "", fmt.Errorf("failed to get resource account, %w", err)
		}
		if getCloudAccountResp.StatusCode() == 404 {
			message.Debug("Humanitec Cloud Account not found: %s, clearing state", session.State.AwsProvider.CreateCloudIdentity.HumanitecCloudAccountId)
			session.State.AwsProvider.CreateCloudIdentity.HumanitecCloudAccountId = ""
		} else if getCloudAccountResp.StatusCode() != 200 {
			return "", fmt.Errorf("humanitec returned unexpected status code: %d with body %s", getCloudAccountResp.StatusCode(), string(getCloudAccountResp.Body))
		}
	}

	if session.State.AwsProvider.CreateCloudIdentity.HumanitecCloudAccountId == "" {
		message.Info("Creating Humanitec Cloud Account: %s", humanitecCloudAccountId)
		if err := createResourceAccountWithRetries(ctx, a.humanitecPlatform.Client, a.humanitecPlatform.OrganizationId, client.CreateResourceAccountRequestRequest{
			Id:   humanitecCloudAccountId,
			Name: humanitecCloudAccountName,
			Type: "aws-role",
			Credentials: map[string]interface{}{
				"aws_role":    session.State.AwsProvider.CreateCloudIdentity.RoleArn,
				"external_id": session.State.AwsProvider.CreateCloudIdentity.ExternalId,
			},
		}, 2*time.Minute); err != nil {
			return "", fmt.Errorf("failed to create resource account, %w", err)
		}

		session.State.AwsProvider.CreateCloudIdentity.HumanitecCloudAccountId = humanitecCloudAccountId
		if err := session.Save(); err != nil {
			return "", fmt.Errorf("failed to save state: %w", err)
		}
		message.Info("Humanitec Cloud Account created: %s", humanitecCloudAccountId)
	} else {
		message.Info("Humanitec Cloud Account already created, loading from state: %s", session.State.AwsProvider.CreateCloudIdentity.HumanitecCloudAccountId)
	}

	return session.State.AwsProvider.CreateCloudIdentity.HumanitecCloudAccountId, nil
}

func (a *awsProvider) ListClusters(ctx context.Context) ([]string, error) {
	eksClient := eks.NewFromConfig(a.awsConfig)
	listClustersResp, err := eksClient.ListClusters(ctx, &eks.ListClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list clusters, %w", err)
	}
	if listClustersResp == nil || listClustersResp.Clusters == nil {
		return nil, fmt.Errorf("failed to list clusters: listClustersResp or listClustersResp.Clusters is nil")
	}

	return listClustersResp.Clusters, nil
}

func (a *awsProvider) ListLoadBalancers(ctx context.Context, clusterId string) ([]string, error) {
	eksClient := eks.NewFromConfig(a.awsConfig)
	clusterResp, err := eksClient.DescribeCluster(ctx, &eks.DescribeClusterInput{
		Name: &clusterId,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe cluster, %w", err)
	}
	if clusterResp == nil || clusterResp.Cluster == nil || clusterResp.Cluster.Arn == nil || clusterResp.Cluster.Name == nil || clusterResp.Cluster.ResourcesVpcConfig == nil || clusterResp.Cluster.ResourcesVpcConfig.VpcId == nil {
		return nil, fmt.Errorf("failed to describe cluster: clusterResp, clusterResp.Cluster, clusterResp.Cluster.Arn, clusterResp.Cluster.Name, clusterResp.Cluster.ResourcesVpcConfig or clusterResp.Cluster.ResourcesVpcConfig.VpcId is nil")
	}

	loadBalancerNames := []string{}

	elbClient := elasticloadbalancing.NewFromConfig(a.awsConfig)
	loadBalancersResp, err := elbClient.DescribeLoadBalancers(ctx, &elasticloadbalancing.DescribeLoadBalancersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe load balancers, %w", err)
	}
	if loadBalancersResp == nil || loadBalancersResp.LoadBalancerDescriptions == nil {
		return nil, fmt.Errorf("failed to describe load balancers: loadBalancersResp or loadBalancersResp.LoadBalancerDescriptions is nil")
	}
	for _, loadBalancerDesc := range loadBalancersResp.LoadBalancerDescriptions {
		if loadBalancerDesc.VPCId == nil || loadBalancerDesc.LoadBalancerName == nil {
			return nil, fmt.Errorf("failed to describe load balancer: loadBalancerDesc.VPCId or loadBalancerDesc.LoadBalancerName is nil")
		}
		if *loadBalancerDesc.VPCId == *clusterResp.Cluster.ResourcesVpcConfig.VpcId {
			loadBalancerNames = append(loadBalancerNames, *loadBalancerDesc.LoadBalancerName)
		}
	}

	elbV2Client := elasticloadbalancingv2.NewFromConfig(a.awsConfig)
	loadBalancersV2Resp, err := elbV2Client.DescribeLoadBalancers(ctx, &elasticloadbalancingv2.DescribeLoadBalancersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe load balancers, %w", err)
	}
	if loadBalancersV2Resp == nil || loadBalancersV2Resp.LoadBalancers == nil {
		return nil, fmt.Errorf("failed to describe load balancers: loadBalancersV2Resp or loadBalancersV2Resp.LoadBalancers is nil")
	}
	for _, loadBalancer := range loadBalancersV2Resp.LoadBalancers {
		if loadBalancer.VpcId == nil || loadBalancer.LoadBalancerName == nil {
			return nil, fmt.Errorf("failed to describe load balancer: loadBalancer.VpcId or loadBalancer.LoadBalancerName is nil")
		}
		if *loadBalancer.VpcId == *clusterResp.Cluster.ResourcesVpcConfig.VpcId {
			loadBalancerNames = append(loadBalancerNames, *loadBalancer.LoadBalancerName)
		}
	}
	return loadBalancerNames, nil
}

func (a *awsProvider) ConnectCluster(ctx context.Context, clusterId, loadBalancerName, humanitecCloudAccountId, humanitecClusterId, humanitecClusterName string) (string, error) {
	err := a.ensureK8sClient(ctx, clusterId)
	if err != nil {
		return "", fmt.Errorf("failed to ensure k8s client, %w", err)
	}

	eksClient := eks.NewFromConfig(a.awsConfig)
	clusterResp, err := eksClient.DescribeCluster(ctx, &eks.DescribeClusterInput{
		Name: &clusterId,
	})
	if err != nil {
		return "", fmt.Errorf("failed to describe cluster, %w", err)
	}
	if clusterResp == nil || clusterResp.Cluster == nil || clusterResp.Cluster.Arn == nil || clusterResp.Cluster.Name == nil || clusterResp.Cluster.AccessConfig == nil {
		return "", fmt.Errorf("failed to describe cluster: clusterResp, clusterResp.Cluster, clusterResp.Cluster.Arn, clusterResp.Cluster.Name or clusterResp.Cluster.AccessConfig is nil")
	}

	iamClient := iam.NewFromConfig(a.awsConfig)

	if session.State.AwsProvider.ConnectCluster.PolicyArn != "" {
		isPolicyExists, err := a.isPolicyExists(ctx, session.State.AwsProvider.ConnectCluster.PolicyArn)
		if err != nil {
			return "", fmt.Errorf("failed to check if policy exists, %w", err)
		}
		if !isPolicyExists {
			message.Debug("AWS Policy not found: %s, clearing state", session.State.AwsProvider.ConnectCluster.PolicyArn)
			session.State.AwsProvider.ConnectCluster.PolicyArn = ""
		}
	}

	if session.State.AwsProvider.ConnectCluster.PolicyArn == "" {
		policyName := generateAwsPolicyName(fmt.Sprintf("humanitec-access-eks-%s", *clusterResp.Cluster.Name))
		policyDocument := fmt.Sprintf(`{
			"Version": "2012-10-17",
			"Statement": [
				{
				"Effect": "Allow",
				"Action": [
					"eks:DescribeNodegroup",
					"eks:ListNodegroups",
					"eks:AccessKubernetesApi",
					"eks:DescribeCluster",
					"eks:ListClusters"
				],
				"Resource": "%s"
				}
			]
		}`, *clusterResp.Cluster.Arn)

		policyDocumentMinified := &bytes.Buffer{}
		if err := json.Compact(policyDocumentMinified, []byte(policyDocument)); err != nil {
			return "", fmt.Errorf("failed to minify role policy, %w", err)
		}

		message.Info("Creating AWS Policy: aws iam create-policy --policy-name %s --policy-document '%s'", policyName, policyDocumentMinified.String())
		createPolicyResp, err := iamClient.CreatePolicy(ctx, &iam.CreatePolicyInput{
			PolicyDocument: &policyDocument,
			PolicyName:     &policyName,
		})
		if err != nil {
			return "", fmt.Errorf("failed to create policy, %w", err)
		}
		if createPolicyResp == nil || createPolicyResp.Policy == nil || createPolicyResp.Policy.Arn == nil {
			return "", fmt.Errorf("failed to create policy: createPolicyResp, createPolicyResp.Policy or createPolicyResp.Policy.Arn is nil")
		}

		session.State.AwsProvider.ConnectCluster.PolicyArn = *createPolicyResp.Policy.Arn
		session.State.AwsProvider.ConnectCluster.PolicyName = *createPolicyResp.Policy.PolicyName
		if err := session.Save(); err != nil {
			return "", fmt.Errorf("failed to save state: %w", err)
		}
		message.Info("AWS Policy created: %s", *createPolicyResp.Policy.PolicyName)
	} else {
		message.Info("AWS Policy already created, loading from state: %s", session.State.AwsProvider.ConnectCluster.PolicyName)
	}

	isPolicyAttached, err := a.isPolicyAttachedToRole(ctx, session.State.AwsProvider.CreateCloudIdentity.RoleName, session.State.AwsProvider.ConnectCluster.PolicyArn)
	if err != nil {
		return "", fmt.Errorf("failed to check if policy is attached to role, %w", err)
	}

	if !isPolicyAttached {
		message.Info("Attaching policy to role: aws iam attach-role-policy --role-name %s --policy-arn %s", session.State.AwsProvider.CreateCloudIdentity.RoleName, session.State.AwsProvider.ConnectCluster.PolicyArn)
		_, err = iamClient.AttachRolePolicy(ctx, &iam.AttachRolePolicyInput{
			PolicyArn: &session.State.AwsProvider.ConnectCluster.PolicyArn,
			RoleName:  &session.State.AwsProvider.CreateCloudIdentity.RoleName,
		})
		if err != nil {
			return "", fmt.Errorf("failed to attach role policy, %w", err)
		}
		message.Info("Policy %s attached to role %s", session.State.AwsProvider.ConnectCluster.PolicyName, session.State.AwsProvider.CreateCloudIdentity.RoleName)
	} else {
		message.Info("Policy %s already attached to role %s", session.State.AwsProvider.ConnectCluster.PolicyName, session.State.AwsProvider.CreateCloudIdentity.RoleName)
	}

	if session.State.AwsProvider.ConnectCluster.K8sRbacGroupName == "" {
		session.State.AwsProvider.ConnectCluster.K8sRbacGroupName = generateAwsK8sGroupName("humanitec-access")
	}
	if err := session.Save(); err != nil {
		return "", fmt.Errorf("failed to save state: %w", err)
	}

	rbacSubject := k8s_rbac.Subject{
		Kind: "Group",
		Name: session.State.AwsProvider.ConnectCluster.K8sRbacGroupName,
	}

	if session.State.AwsProvider.ConnectCluster.K8s == nil {
		session.State.AwsProvider.ConnectCluster.K8s = &session.K8s{}
	}
	if err = createClusterRoleAndBinding(ctx, a.k8sClient, rbacSubject, session.State.AwsProvider.ConnectCluster.K8s); err != nil {
		return "", err
	}
	if err := session.Save(); err != nil {
		return "", fmt.Errorf("failed to save state: %w", err)
	}

	if clusterResp.Cluster.AccessConfig.AuthenticationMode == types.AuthenticationModeConfigMap {
		configMap, err := a.k8sClient.CoreV1().ConfigMaps("kube-system").Get(ctx, "aws-auth", k8s_meta.GetOptions{})
		if err != nil {
			if !k8sErrors.IsNotFound(err) {
				return "", fmt.Errorf("failed to get ConfigMap 'aws-auth': %w", err)
			}
			configMap = &v1.ConfigMap{}
			configMap.APIVersion = "v1"
		}
		if configMap.Data == nil {
			configMap.Data = map[string]string{}
		}

		if configMap.Data["mapRoles"] == "" || !strings.Contains(configMap.Data["mapRoles"], session.State.AwsProvider.CreateCloudIdentity.RoleArn) {
			configMap.Data["mapRoles"] = strings.Join([]string{
				configMap.Data["mapRoles"],
				"- rolearn: " + session.State.AwsProvider.CreateCloudIdentity.RoleArn,
				"  username: system:node:{{EC2PrivateDNSName}}",
				"  groups:",
				"  - " + session.State.AwsProvider.ConnectCluster.K8sRbacGroupName,
			}, "\n")

			message.Info("Updating ConfigMap 'aws-auth' with role %s", session.State.AwsProvider.CreateCloudIdentity.RoleArn)
			_, err = a.k8sClient.CoreV1().ConfigMaps("kube-system").Update(ctx, configMap, k8s_meta.UpdateOptions{})
			if err != nil {
				return "", fmt.Errorf("failed to update ConfigMap 'aws-auth': %w", err)
			}
		}
	} else {
		isAccessEntryCreated, err := a.isAccessEntryExists(ctx, *clusterResp.Cluster.Name, session.State.AwsProvider.CreateCloudIdentity.RoleArn)
		if err != nil {
			return "", fmt.Errorf("failed to check if access entry exists, %w", err)
		}

		if !isAccessEntryCreated {
			message.Info("Creating AWS Access Entry: aws eks create-access-entry --cluster-name %s --principal-arn %s --kubernetes-groups %s", *clusterResp.Cluster.Name, session.State.AwsProvider.CreateCloudIdentity.RoleArn, session.State.AwsProvider.ConnectCluster.K8sRbacGroupName)
			_, err = eksClient.CreateAccessEntry(ctx, &eks.CreateAccessEntryInput{
				ClusterName:  clusterResp.Cluster.Name,
				PrincipalArn: &session.State.AwsProvider.CreateCloudIdentity.RoleArn,
				KubernetesGroups: []string{
					session.State.AwsProvider.ConnectCluster.K8sRbacGroupName,
				},
			})
			if err != nil {
				return "", fmt.Errorf("failed to create access entry, %w", err)
			}
			message.Info("AWS Access Entry to cluster %s created for %s", *clusterResp.Cluster.Name, session.State.AwsProvider.CreateCloudIdentity.RoleArn)
		} else {
			message.Info("AWS Access Entry to cluster %s already created for %s", *clusterResp.Cluster.Name, session.State.AwsProvider.CreateCloudIdentity.RoleArn)
		}
	}

	clusterValues := map[string]interface{}{
		"region": a.awsConfig.Region,
		"name":   *clusterResp.Cluster.Name,
	}

	if utils.IsIpLbAddress(loadBalancerName) {
		clusterValues["loadbalancer"] = loadBalancerName
	} else {
		var loadbalancerDNSName, loadBalancerCanonicalHostedZoneId string
		elbClient := elasticloadbalancing.NewFromConfig(a.awsConfig)
		loadBalancersResp, err := elbClient.DescribeLoadBalancers(ctx, &elasticloadbalancing.DescribeLoadBalancersInput{})
		if err != nil {
			return "", fmt.Errorf("failed to describe load balancers, %w", err)
		}
		if loadBalancersResp == nil || loadBalancersResp.LoadBalancerDescriptions == nil {
			return "", fmt.Errorf("failed to describe load balancers: loadBalancersResp or loadBalancersResp.LoadBalancerDescriptions is nil")
		}
		for _, loadBalancerDesc := range loadBalancersResp.LoadBalancerDescriptions {
			if loadBalancerDesc.LoadBalancerName == nil {
				return "", fmt.Errorf("failed to describe load balancer: loadBalancerDesc.LoadBalancerName is nil")
			}
			if *loadBalancerDesc.LoadBalancerName == loadBalancerName {
				if loadBalancerDesc.DNSName == nil || loadBalancerDesc.CanonicalHostedZoneNameID == nil {
					return "", fmt.Errorf("failed to describe load balancer: loadBalancerDesc.DNSName or loadBalancerDesc.CanonicalHostedZoneNameID is nil")
				}
				loadbalancerDNSName = *loadBalancerDesc.DNSName
				loadBalancerCanonicalHostedZoneId = *loadBalancerDesc.CanonicalHostedZoneNameID
			}
		}

		elbV2Client := elasticloadbalancingv2.NewFromConfig(a.awsConfig)
		loadBalancersV2Resp, err := elbV2Client.DescribeLoadBalancers(ctx, &elasticloadbalancingv2.DescribeLoadBalancersInput{})
		if err != nil {
			return "", fmt.Errorf("failed to describe load balancers, %w", err)
		}
		if loadBalancersV2Resp == nil || loadBalancersV2Resp.LoadBalancers == nil {
			return "", fmt.Errorf("failed to describe load balancers: loadBalancersV2Resp or loadBalancersV2Resp.LoadBalancers is nil")
		}
		for _, loadBalancer := range loadBalancersV2Resp.LoadBalancers {
			if loadBalancer.LoadBalancerName == nil {
				return "", fmt.Errorf("failed to describe load balancer: loadBalancer.LoadBalancerName is nil")
			}
			if *loadBalancer.LoadBalancerName == loadBalancerName {
				if loadBalancer.DNSName == nil || loadBalancer.CanonicalHostedZoneId == nil {
					return "", fmt.Errorf("failed to describe load balancer: loadBalancer.DNSName or loadBalancer.CanonicalHostedZoneId is nil")
				}
				loadbalancerDNSName = *loadBalancer.DNSName
				loadBalancerCanonicalHostedZoneId = *loadBalancer.CanonicalHostedZoneId
			}
		}
		if loadbalancerDNSName == "" || loadBalancerCanonicalHostedZoneId == "" {
			return "", fmt.Errorf("failed to describe load balancer: loadbalancerDNSName or loadBalancerCanonicalHostedZoneId is empty")
		}
		clusterValues["loadbalancer"] = loadbalancerDNSName
		clusterValues["loadbalancer_hosted_zone"] = loadBalancerCanonicalHostedZoneId
	}

	isHumanitecClusterResourceCreated, err := a.isHumanitecResourceExists(ctx, humanitecClusterId)
	if err != nil {
		return "", fmt.Errorf("failed to check if humanitec resource cluster exists, %w", err)
	}

	if !isHumanitecClusterResourceCreated {
		message.Info("Creating Humanitec Resource Cluster: %s", humanitecClusterId)
		createResourceResp, err := a.humanitecPlatform.Client.CreateResourceDefinitionWithResponse(ctx, a.humanitecPlatform.OrganizationId, client.CreateResourceDefinitionRequestRequest{
			Id:            humanitecClusterId,
			Name:          humanitecClusterName,
			Type:          "k8s-cluster",
			DriverAccount: &humanitecCloudAccountId,
			DriverType:    "humanitec/k8s-cluster-eks",
			DriverInputs: &client.ValuesSecretsRefsRequest{
				Values: &clusterValues,
			},
		})
		if err != nil {
			return "", fmt.Errorf("failed to create resource definition, %w", err)
		}
		if createResourceResp.StatusCode() != 200 {
			return "", fmt.Errorf("humanitec returned unexpected status code: %d with body %s", createResourceResp.StatusCode(), string(createResourceResp.Body))
		}
		message.Info("Humanitec Resource Cluster created: %s", humanitecClusterId)
	} else {
		message.Info("Humanitec Resource Cluster already created: %s", humanitecClusterId)
	}

	return humanitecClusterId, nil
}

func (a *awsProvider) IsClusterPubliclyAvailable(ctx context.Context, clusterId string) (bool, error) {
	eksClient := eks.NewFromConfig(a.awsConfig)
	clusterResp, err := eksClient.DescribeCluster(ctx, &eks.DescribeClusterInput{
		Name: &clusterId,
	})
	if err != nil {
		return false, fmt.Errorf("failed to describe cluster, %w", err)
	}
	if clusterResp == nil || clusterResp.Cluster == nil || clusterResp.Cluster.ResourcesVpcConfig == nil {
		return false, fmt.Errorf("failed to describe cluster: clusterResp, clusterResp.Cluster or clusterResp.Cluster.ResourcesVpcConfig is nil")
	}

	return clusterResp.Cluster.ResourcesVpcConfig.EndpointPublicAccess, nil
}

func (a *awsProvider) WriteKubeConfig(ctx context.Context, clusterId string) (string, error) {
	kubeConfig, err := a.getKubeConfig(ctx, clusterId)
	if err != nil {
		return "", fmt.Errorf("failed to get kubeconfig, %w", err)
	}

	dirname, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %w", err)
	}

	pathToKubeConfig := path.Join(dirname, ".humanitec-setup-wizard", "kubeconfig")

	if err = clientcmd.WriteToFile(*kubeConfig, pathToKubeConfig); err != nil {
		return "", fmt.Errorf("failed to write kubeconfig to file, %w", err)
	}

	return pathToKubeConfig, nil
}

func (a *awsProvider) getKubeConfig(ctx context.Context, clusterId string) (*api.Config, error) {
	eksClient := eks.NewFromConfig(a.awsConfig)
	cluster, err := eksClient.DescribeCluster(ctx, &eks.DescribeClusterInput{
		Name: &clusterId,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe cluster, %w", err)
	}
	if cluster == nil || cluster.Cluster == nil || cluster.Cluster.CertificateAuthority == nil || cluster.Cluster.Endpoint == nil {
		return nil, fmt.Errorf("failed to describe cluster: cluster, cluster.Cluster, cluster.Cluster.CertificateAuthority or cluster.Cluster.Endpoint is nil")
	}
	gen, err := token.NewGenerator(true, false)
	if err != nil {
		return nil, fmt.Errorf("failed to create token generator, %w", err)
	}
	opts := &token.GetTokenOptions{
		ClusterID: clusterId,
	}
	token, err := gen.GetWithOptions(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get token, %w", err)
	}
	ca, err := base64.StdEncoding.DecodeString(*cluster.Cluster.CertificateAuthority.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate authority, %w", err)
	}

	kubeConfig := generateKubeConfig(*cluster.Cluster.Endpoint, token.Token, ca)
	return &kubeConfig, nil
}

func (a *awsProvider) ListSecretManagers(ctx context.Context) ([]string, error) {
	return []string{"aws-secret-manager"}, nil
}

func (a *awsProvider) ConfigureOperator(ctx context.Context, platform *platform.HumanitecPlatform, kubeconfig, operatorNamespace, clusterId, secretManager, humanitecSecretStoreId string) error {
	err := a.ensureK8sClient(ctx, clusterId)
	if err != nil {
		return fmt.Errorf("failed to ensure k8s client, %w", err)
	}

	accountId, err := a.getAccountId(ctx)
	if err != nil {
		return fmt.Errorf("failed to get calling user id, %w", err)
	}

	secretsManagerPolicyResourceArn := fmt.Sprintf("arn:aws:secretsmanager:%s:%s:secret:*", a.awsConfig.Region, accountId)

	iamClient := iam.NewFromConfig(a.awsConfig)
	eksClient := eks.NewFromConfig(a.awsConfig)

	if session.State.AwsProvider.ConfigureOperatorAccess.AccessSecretsManagerPolicyARN != "" {
		isAccessSecretsManagerPolicyCreated, err := a.isPolicyExists(ctx, session.State.AwsProvider.ConfigureOperatorAccess.AccessSecretsManagerPolicyARN)
		if err != nil {
			return fmt.Errorf("failed to check if policy exists, %w", err)
		}
		if !isAccessSecretsManagerPolicyCreated {
			message.Debug("Secret access policy not found: %s, clearing state", session.State.AwsProvider.ConfigureOperatorAccess.AccessSecretsManagerPolicyName)
			session.State.AwsProvider.ConfigureOperatorAccess.AccessSecretsManagerPolicyName = ""
			session.State.AwsProvider.ConfigureOperatorAccess.AccessSecretsManagerPolicyARN = ""
			if err = session.Save(); err != nil {
				return fmt.Errorf("failed to save state: %w", err)
			}
		}
	}

	if session.State.AwsProvider.ConfigureOperatorAccess.AccessSecretsManagerPolicyARN == "" {
		secretsManagerAccessPolicyName := generateAwsPolicyName("secrets-manager-access")
		secretsManagerAccessPolicy := fmt.Sprintf(`{
			"Version": "2012-10-17",
			"Statement": {
			  "Effect": "Allow",
				"Action": [
				  "secretsmanager:GetSecretValue",
				  "secretsmanager:CreateSecret",
				  "secretsmanager:DeleteSecret",
				  "secretsmanager:PutSecretValue",
				  "secretsmanager:RestoreSecret"
				],
			  "Resource": "%s"
			}
		  }`, secretsManagerPolicyResourceArn)

		secretsManagerAccessPolicyMinified := &bytes.Buffer{}
		if err := json.Compact(secretsManagerAccessPolicyMinified, []byte(secretsManagerAccessPolicy)); err != nil {
			return fmt.Errorf("failed to minify secrets manager access policy, %w", err)
		}

		message.Info("Creating Secret Access Policy: aws iam create-policy --policy-name %s --policy-document '%s'", secretsManagerAccessPolicyName, secretsManagerAccessPolicyMinified.String())
		createPolicyResp, err := iamClient.CreatePolicy(ctx, &iam.CreatePolicyInput{
			PolicyDocument: &secretsManagerAccessPolicy,
			PolicyName:     &secretsManagerAccessPolicyName,
		})
		if err != nil {
			return fmt.Errorf("failed to create secret access policy, %w", err)
		}
		if createPolicyResp == nil || createPolicyResp.Policy == nil || createPolicyResp.Policy.Arn == nil {
			return fmt.Errorf("failed to create secret access policy: createPolicyResp, createPolicyResp.Policy or createPolicyResp.Policy.Arn is nil")
		}
		session.State.AwsProvider.ConfigureOperatorAccess.AccessSecretsManagerPolicyARN = *createPolicyResp.Policy.Arn
		session.State.AwsProvider.ConfigureOperatorAccess.AccessSecretsManagerPolicyName = secretsManagerAccessPolicyName
		if err := session.Save(); err != nil {
			return fmt.Errorf("failed to save state: %w", err)
		}
		message.Debug("Secret access policy created: %s", *createPolicyResp.Policy.PolicyName)
	} else {
		message.Debug("Secret access policy already created, loading from state: %s", session.State.AwsProvider.ConfigureOperatorAccess.AccessSecretsManagerPolicyName)
	}

	if session.State.AwsProvider.ConfigureOperatorAccess.TrustPolicyRoleName != "" {
		isTrustPolicyRoleCreated, err := a.isRoleExists(ctx, session.State.AwsProvider.ConfigureOperatorAccess.TrustPolicyRoleName)
		if err != nil {
			return fmt.Errorf("failed to check if role exists, %w", err)
		}
		if !isTrustPolicyRoleCreated {
			message.Debug("Trust policy role not found: %s, clearing state", session.State.AwsProvider.ConfigureOperatorAccess.TrustPolicyRoleName)
			session.State.AwsProvider.ConfigureOperatorAccess.TrustPolicyRoleName = ""
			session.State.AwsProvider.ConfigureOperatorAccess.TrustPolicyRoleARN = ""
			if err = session.Save(); err != nil {
				return fmt.Errorf("failed to save state: %w", err)
			}
		}
	}

	if session.State.AwsProvider.ConfigureOperatorAccess.TrustPolicyRoleName == "" {
		trustPolicyRoleName := generateAwsRoleName("humanitec-operator-sa")
		trustPolicyRoleDescription := "Humanitec Operator service account on EKS cluster"
		trustPolicy := `{
			"Version": "2012-10-17",
			"Statement": [
				{
					"Sid": "AllowEksAuthToAssumeRoleForPodIdentity",
					"Effect": "Allow",
					"Principal": {
						"Service": "pods.eks.amazonaws.com"
					},
					"Action": [
						"sts:AssumeRole",
						"sts:TagSession"
					]
				}
			]
		}`

		trustPolicyMinified := &bytes.Buffer{}
		if err := json.Compact(trustPolicyMinified, []byte(trustPolicy)); err != nil {
			return fmt.Errorf("failed to minify trust policy, %w", err)
		}

		message.Info("Creating Trust Policy Role: aws iam create-role --role-name %s --description %s --assume-role-policy-document '%s'", trustPolicyRoleName, trustPolicyRoleDescription, trustPolicyMinified.String())
		createRoleResp, err := iamClient.CreateRole(ctx, &iam.CreateRoleInput{
			RoleName:                 &trustPolicyRoleName,
			Description:              &trustPolicyRoleDescription,
			AssumeRolePolicyDocument: &trustPolicy,
		})
		if err != nil {
			return fmt.Errorf("failed to create role, %w", err)
		}
		if createRoleResp == nil || createRoleResp.Role == nil || createRoleResp.Role.Arn == nil {
			return fmt.Errorf("failed to create role: createRoleResp, createRoleResp.Role or createRoleResp.Role.Arn is nil")
		}
		session.State.AwsProvider.ConfigureOperatorAccess.TrustPolicyRoleARN = *createRoleResp.Role.Arn
		session.State.AwsProvider.ConfigureOperatorAccess.TrustPolicyRoleName = trustPolicyRoleName
		if err = session.Save(); err != nil {
			return fmt.Errorf("failed to save state: %w", err)
		}
		message.Info("Trust policy role created: %s", *createRoleResp.Role.Arn)
	} else {
		message.Info("Trust policy role already created, loading from state: %s", session.State.AwsProvider.ConfigureOperatorAccess.TrustPolicyRoleName)
	}

	isAccessSecretPolicyAttached, err := a.isPolicyAttachedToRole(ctx, session.State.AwsProvider.ConfigureOperatorAccess.TrustPolicyRoleName, session.State.AwsProvider.ConfigureOperatorAccess.AccessSecretsManagerPolicyARN)
	if err != nil {
		return fmt.Errorf("failed to check if policy is attached to role, %w", err)
	}
	if !isAccessSecretPolicyAttached {
		message.Info("Attaching policy to role: aws iam attach-role-policy --role-name %s --policy-arn %s", session.State.AwsProvider.ConfigureOperatorAccess.TrustPolicyRoleName, session.State.AwsProvider.ConfigureOperatorAccess.AccessSecretsManagerPolicyARN)
		_, err = iamClient.AttachRolePolicy(ctx, &iam.AttachRolePolicyInput{
			PolicyArn: &session.State.AwsProvider.ConfigureOperatorAccess.AccessSecretsManagerPolicyARN,
			RoleName:  &session.State.AwsProvider.ConfigureOperatorAccess.TrustPolicyRoleName,
		})
		if err != nil {
			return fmt.Errorf("failed to attach role policy, %w", err)
		}
		message.Info("Policy %s attached to role %s", session.State.AwsProvider.ConfigureOperatorAccess.AccessSecretsManagerPolicyName, session.State.AwsProvider.ConfigureOperatorAccess.TrustPolicyRoleName)
	} else {
		message.Info("Policy %s already attached to role %s", session.State.AwsProvider.ConfigureOperatorAccess.AccessSecretsManagerPolicyName, session.State.AwsProvider.ConfigureOperatorAccess.TrustPolicyRoleName)
	}

	if session.State.AwsProvider.ConfigureOperatorAccess.PodIdentityAssociationId != "" {
		isPodIdentityAssociationCreated, err := a.isPodIdentityAssociationExists(ctx, clusterId, session.State.AwsProvider.ConfigureOperatorAccess.PodIdentityAssociationId)
		if err != nil {
			return fmt.Errorf("failed to check if pod identity association exists, %w", err)
		}
		if !isPodIdentityAssociationCreated {
			message.Debug("Pod identity association not found: %s, clearing state", session.State.AwsProvider.ConfigureOperatorAccess.PodIdentityAssociationId)
			session.State.AwsProvider.ConfigureOperatorAccess.PodIdentityAssociationId = ""
			if err = session.Save(); err != nil {
				return fmt.Errorf("failed to save state: %w", err)
			}
		}
	}

	if session.State.AwsProvider.ConfigureOperatorAccess.PodIdentityAssociationId == "" {
		message.Info("Creating Pod Identity Association: aws eks create-pod-identity-association --cluster-name %s --namespace %s --service-account %s --role-arn %s", clusterId, operatorNamespace, humanitecOperatorServiceAccount, session.State.AwsProvider.ConfigureOperatorAccess.TrustPolicyRoleARN)
		createPodIdentityAssociationResp, err := eksClient.CreatePodIdentityAssociation(ctx, &eks.CreatePodIdentityAssociationInput{
			ClusterName:    &clusterId,
			Namespace:      &operatorNamespace,
			ServiceAccount: &humanitecOperatorServiceAccount,
			RoleArn:        &session.State.AwsProvider.ConfigureOperatorAccess.TrustPolicyRoleARN,
		})
		if err != nil {
			return fmt.Errorf("failed to create pod identity association, %w", err)
		}
		session.State.AwsProvider.ConfigureOperatorAccess.PodIdentityAssociationId = *createPodIdentityAssociationResp.Association.AssociationId
		if err = session.Save(); err != nil {
			return fmt.Errorf("failed to save state: %w", err)
		}
		message.Info("Pod identity association created: %s", *createPodIdentityAssociationResp.Association.AssociationId)
	} else {
		message.Info("Pod identity association already created: %s, loading from state", session.State.AwsProvider.ConfigureOperatorAccess.PodIdentityAssociationId)
	}

	message.Info("Creating Humanitec Secret Store configuration: %s", humanitecSecretStoreId)
	err = cluster.ApplySecretStore(ctx, kubeconfig, operatorNamespace, humanitecSecretStoreId, &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "humanitec.io/v1alpha1",
			"kind":       "SecretStore",
			"metadata": map[string]interface{}{
				"name":      humanitecSecretStoreId,
				"namespace": operatorNamespace,
				"labels": map[string]interface{}{
					"app.humanitec.io/default-store": "true",
				},
			},
			"spec": map[string]interface{}{
				"awssm": map[string]interface{}{
					"region": a.awsConfig.Region,
					"auth":   map[string]interface{}{},
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to register secret store, %w", err)
	}

	err = a.restartOperatorUntilPodIsReady(ctx, kubeconfig, operatorNamespace)
	if err != nil {
		return fmt.Errorf("failed to restart operator deployment, %w", err)
	}
	message.Info("Operator deployment restarted")

	if session.State.AwsProvider.ConfigureOperatorAccess.SecretStoreId != "" {
		isSecretStoreCreated, err := a.isHumanitecSecretStoreResourceCreated(ctx, session.State.AwsProvider.ConfigureOperatorAccess.SecretStoreId)
		if err != nil {
			return fmt.Errorf("failed to check if secret store exists, %w", err)
		}
		if !isSecretStoreCreated {
			message.Debug("Secret store not found: %s, clearing state", session.State.AwsProvider.ConfigureOperatorAccess.SecretStoreId)
			session.State.AwsProvider.ConfigureOperatorAccess.SecretStoreId = ""
			if err = session.Save(); err != nil {
				return fmt.Errorf("failed to save state: %w", err)
			}
		}
	}

	if session.State.AwsProvider.ConfigureOperatorAccess.SecretStoreId == "" {
		message.Info("Registering Secret Store with Humanitec: %s", humanitecSecretStoreId)
		createSecretStore, err := platform.Client.PostOrgsOrgIdSecretstoresWithResponse(ctx, platform.OrganizationId, client.PostOrgsOrgIdSecretstoresJSONRequestBody{
			Id:      humanitecSecretStoreId,
			Primary: true,
			Awssm: &client.AWSSMRequest{
				Region: &a.awsConfig.Region,
			},
		})
		if err != nil {
			return fmt.Errorf("failed to create secret store, %w", err)
		}
		if createSecretStore.StatusCode() != 201 {
			return fmt.Errorf("humanitec returned unexpected status code: %d with body %s", createSecretStore.StatusCode(), string(createSecretStore.Body))
		}
		session.State.AwsProvider.ConfigureOperatorAccess.SecretStoreId = humanitecSecretStoreId
		if err = session.Save(); err != nil {
			return fmt.Errorf("failed to save state: %w", err)
		}
		message.Info("Secret store created: %s", humanitecSecretStoreId)
	} else {
		message.Info("Secret store already created: %s, loading from state", session.State.AwsProvider.ConfigureOperatorAccess.SecretStoreId)
	}

	return nil
}

func (a *awsProvider) restartOperatorUntilPodIsReady(ctx context.Context, kubeconfig, namespace string) error {
	message.Info("Restarting operator deployment")
	err := cluster.RestartOperatorDeployment(ctx, kubeconfig, namespace)
	if err != nil {
		return fmt.Errorf("failed to restart operator deployment, %w", err)
	}

	timeout := time.After(5 * time.Minute)
	tick := time.Tick(5 * time.Second)

mainLoop:
	for {
		select {
		case <-timeout:
			return fmt.Errorf("timed out waiting for operator deployment to be ready")
		case <-tick:
			deployment, err := a.k8sClient.AppsV1().Deployments(namespace).Get(ctx, "humanitec-operator-controller-manager", k8s_meta.GetOptions{})
			if err != nil {
				return fmt.Errorf("failed to get operator deployment, %w", err)
			}

			if deployment.Status.Replicas != *deployment.Spec.Replicas {
				message.Debug("Operator deployment is not ready, waiting for it to be ready")
				continue mainLoop
			}

			selector, err := k8s_meta.LabelSelectorAsSelector(deployment.Spec.Selector)
			if err != nil {
				return fmt.Errorf("failed to get operator deployment selector, %w", err)
			}

			pods, err := a.k8sClient.CoreV1().Pods(namespace).List(ctx, k8s_meta.ListOptions{
				LabelSelector: selector.String(),
			})
			if err != nil {
				return fmt.Errorf("failed to list operator pods, %w", err)
			}

			if a.isOperatorPodReady(*pods) {
				break mainLoop
			}

			err = cluster.RestartOperatorDeployment(ctx, kubeconfig, namespace)
			if err != nil {
				return fmt.Errorf("failed to restart operator deployment, %w", err)
			}
		}
	}
	return nil
}

func (*awsProvider) isOperatorPodReady(pods v1.PodList) bool {
	atLeastOnePodReady := false
	for _, pod := range pods.Items {
		for _, container := range pod.Spec.Containers {
			if container.Name == "manager" {
				isAuthorizationTokenFileSet := false
				for _, env := range container.Env {
					if env.Name == "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE" {
						isAuthorizationTokenFileSet = true
						break
					}
				}
				if isAuthorizationTokenFileSet {
					atLeastOnePodReady = true
					break
				}
			}
		}
		if atLeastOnePodReady {
			break
		}
	}
	if atLeastOnePodReady {
		return true
	} else {
		message.Debug("Operator pod is not ready, waiting for it to be ready")
		return false
	}
}

func (a *awsProvider) CleanState(ctx context.Context) error {
	eksClient := eks.NewFromConfig(a.awsConfig)
	iamClient := iam.NewFromConfig(a.awsConfig)
	clusterId := session.State.Application.Connect.CloudClusterId

	if session.State.AwsProvider.ConfigureOperatorAccess.PodIdentityAssociationId != "" {
		isPodIdentityAssociationCreated, err := a.isPodIdentityAssociationExists(ctx, clusterId, session.State.AwsProvider.ConfigureOperatorAccess.PodIdentityAssociationId)
		if err != nil {
			return fmt.Errorf("failed to check if pod identity association exists, %w", err)
		}
		if !isPodIdentityAssociationCreated {
			message.Debug("Pod identity association not found: %s, clearing state", session.State.AwsProvider.ConfigureOperatorAccess.PodIdentityAssociationId)
			session.State.AwsProvider.ConfigureOperatorAccess.PodIdentityAssociationId = ""
			if err = session.Save(); err != nil {
				return fmt.Errorf("failed to save state: %w", err)
			}
		} else {
			message.Info("Pod identity association will be deleted: aws eks delete-pod-identity-association --cluster-name %s --association-id %s", clusterId, session.State.AwsProvider.ConfigureOperatorAccess.PodIdentityAssociationId)
			answer, err := message.BoolSelect("Proceed?")
			if err != nil {
				return fmt.Errorf("failed to select answer, %w", err)
			}
			if answer {
				_, err = eksClient.DeletePodIdentityAssociation(ctx, &eks.DeletePodIdentityAssociationInput{
					AssociationId: &session.State.AwsProvider.ConfigureOperatorAccess.PodIdentityAssociationId,
					ClusterName:   &clusterId,
				})
				if err != nil {
					return fmt.Errorf("failed to delete pod identity association, %w", err)
				}
				message.Info("Pod identity association deleted: %s", session.State.AwsProvider.ConfigureOperatorAccess.PodIdentityAssociationId)
				session.State.AwsProvider.ConfigureOperatorAccess.PodIdentityAssociationId = ""
				if err = session.Save(); err != nil {
					return fmt.Errorf("failed to save state: %w", err)
				}
			} else {
				message.Info("Skipping deletion of the pod identity association: %s", session.State.AwsProvider.ConfigureOperatorAccess.PodIdentityAssociationId)
			}
		}

	}

	isAccessSecretPolicyAttached, err := a.isPolicyAttachedToRole(ctx, session.State.AwsProvider.ConfigureOperatorAccess.TrustPolicyRoleName, session.State.AwsProvider.ConfigureOperatorAccess.AccessSecretsManagerPolicyARN)
	if err != nil {
		return fmt.Errorf("failed to check if policy is attached to role, %w", err)
	}
	if isAccessSecretPolicyAttached {
		message.Info("Policy will be detached from role: aws iam detach-role-policy --role-name %s --policy-arn %s", session.State.AwsProvider.ConfigureOperatorAccess.TrustPolicyRoleName, session.State.AwsProvider.ConfigureOperatorAccess.AccessSecretsManagerPolicyARN)
		answer, err := message.BoolSelect("Proceed?")
		if err != nil {
			return fmt.Errorf("failed to select answer, %w", err)
		}
		if answer {
			_, err = iamClient.DetachRolePolicy(ctx, &iam.DetachRolePolicyInput{
				PolicyArn: &session.State.AwsProvider.ConfigureOperatorAccess.AccessSecretsManagerPolicyARN,
				RoleName:  &session.State.AwsProvider.ConfigureOperatorAccess.TrustPolicyRoleName,
			})
			if err != nil {
				return fmt.Errorf("failed to detach role policy, %w", err)
			}
			message.Info("Policy %s detached from role %s", session.State.AwsProvider.ConfigureOperatorAccess.AccessSecretsManagerPolicyName, session.State.AwsProvider.ConfigureOperatorAccess.TrustPolicyRoleName)
		} else {
			message.Info("Skipping detachment of the policy %s from role %s", session.State.AwsProvider.ConfigureOperatorAccess.AccessSecretsManagerPolicyName, session.State.AwsProvider.ConfigureOperatorAccess.TrustPolicyRoleName)
		}
	}

	if session.State.AwsProvider.ConfigureOperatorAccess.TrustPolicyRoleName != "" {
		isTrustPolicyRoleCreated, err := a.isRoleExists(ctx, session.State.AwsProvider.ConfigureOperatorAccess.TrustPolicyRoleName)
		if err != nil {
			return fmt.Errorf("failed to check if role exists, %w", err)
		}
		if !isTrustPolicyRoleCreated {
			message.Debug("Trust policy role not found: %s, clearing state", session.State.AwsProvider.ConfigureOperatorAccess.TrustPolicyRoleName)
			session.State.AwsProvider.ConfigureOperatorAccess.TrustPolicyRoleName = ""
			session.State.AwsProvider.ConfigureOperatorAccess.TrustPolicyRoleARN = ""
			if err = session.Save(); err != nil {
				return fmt.Errorf("failed to save state: %w", err)
			}
		} else {
			message.Info("Trust policy role will be deleted: aws iam delete-role --role-name %s", session.State.AwsProvider.ConfigureOperatorAccess.TrustPolicyRoleName)
			answer, err := message.BoolSelect("Proceed?")
			if err != nil {
				return fmt.Errorf("failed to select answer, %w", err)
			}
			if answer {
				_, err = iamClient.DeleteRole(ctx, &iam.DeleteRoleInput{
					RoleName: &session.State.AwsProvider.ConfigureOperatorAccess.TrustPolicyRoleName,
				})
				if err != nil {
					return fmt.Errorf("failed to delete role, %w", err)
				}
				message.Info("Trust policy role deleted: %s", session.State.AwsProvider.ConfigureOperatorAccess.TrustPolicyRoleName)
				session.State.AwsProvider.ConfigureOperatorAccess.TrustPolicyRoleName = ""
				session.State.AwsProvider.ConfigureOperatorAccess.TrustPolicyRoleARN = ""
				if err = session.Save(); err != nil {
					return fmt.Errorf("failed to save state: %w", err)
				}
			} else {
				message.Info("Skipping deletion of the trust policy role: %s", session.State.AwsProvider.ConfigureOperatorAccess.TrustPolicyRoleName)
			}
		}
	}

	if session.State.AwsProvider.ConfigureOperatorAccess.AccessSecretsManagerPolicyARN != "" {
		isAccessSecretsManagerPolicyCreated, err := a.isPolicyExists(ctx, session.State.AwsProvider.ConfigureOperatorAccess.AccessSecretsManagerPolicyARN)
		if err != nil {
			return fmt.Errorf("failed to check if policy exists, %w", err)
		}
		if !isAccessSecretsManagerPolicyCreated {
			message.Debug("Secret access policy not found: %s, clearing state", session.State.AwsProvider.ConfigureOperatorAccess.AccessSecretsManagerPolicyName)
			session.State.AwsProvider.ConfigureOperatorAccess.AccessSecretsManagerPolicyName = ""
			session.State.AwsProvider.ConfigureOperatorAccess.AccessSecretsManagerPolicyARN = ""
			if err = session.Save(); err != nil {
				return fmt.Errorf("failed to save state: %w", err)
			}
		} else {
			message.Info("Access policy will be deleted: aws iam delete-policy --policy-arn %s", session.State.AwsProvider.ConfigureOperatorAccess.AccessSecretsManagerPolicyARN)
			answer, err := message.BoolSelect("Proceed?")
			if err != nil {
				return fmt.Errorf("failed to select answer, %w", err)
			}
			if answer {
				_, err = iamClient.DeletePolicy(ctx, &iam.DeletePolicyInput{
					PolicyArn: &session.State.AwsProvider.ConfigureOperatorAccess.AccessSecretsManagerPolicyARN,
				})
				if err != nil {
					return fmt.Errorf("failed to delete policy, %w", err)
				}
				message.Info("Access policy deleted: %s", session.State.AwsProvider.ConfigureOperatorAccess.AccessSecretsManagerPolicyName)
				session.State.AwsProvider.ConfigureOperatorAccess.AccessSecretsManagerPolicyName = ""
				session.State.AwsProvider.ConfigureOperatorAccess.AccessSecretsManagerPolicyARN = ""
				if err = session.Save(); err != nil {
					return fmt.Errorf("failed to save state: %w", err)
				}
			} else {
				message.Info("Skipping deletion of the access policy: %s", session.State.AwsProvider.ConfigureOperatorAccess.AccessSecretsManagerPolicyName)
			}
		}
	}

	isAccessEntryCreated, err := a.isAccessEntryExists(ctx, clusterId, session.State.AwsProvider.CreateCloudIdentity.RoleArn)
	if err != nil {
		return fmt.Errorf("failed to check if access entry exists, %w", err)
	}
	if isAccessEntryCreated {
		message.Info("Access entry will be deleted: aws eks delete-access-entry --cluster-name %s --principal-arn %s", clusterId, session.State.AwsProvider.CreateCloudIdentity.RoleArn)
		answer, err := message.BoolSelect("Proceed?")
		if err != nil {
			return fmt.Errorf("failed to select answer, %w", err)
		}
		if answer {
			_, err = eksClient.DeleteAccessEntry(ctx, &eks.DeleteAccessEntryInput{
				ClusterName:  &clusterId,
				PrincipalArn: &session.State.AwsProvider.CreateCloudIdentity.RoleArn,
			})
			if err != nil {
				return fmt.Errorf("failed to delete access entry, %w", err)
			}
			message.Info("Access Entry to cluster %s deleted for %s", clusterId, session.State.AwsProvider.CreateCloudIdentity.RoleArn)
		} else {
			message.Info("Skipping deletion of the access entry: %s", session.State.AwsProvider.CreateCloudIdentity.RoleArn)
		}
	}

	isPolicyAttached, err := a.isPolicyAttachedToRole(ctx, session.State.AwsProvider.CreateCloudIdentity.RoleName, session.State.AwsProvider.ConnectCluster.PolicyArn)
	if err != nil {
		return fmt.Errorf("failed to check if policy is attached to role, %w", err)
	}
	if isPolicyAttached {
		message.Info("Policy will be detached from role: aws iam detach-role-policy --role-name %s --policy-arn %s", session.State.AwsProvider.CreateCloudIdentity.RoleName, session.State.AwsProvider.ConnectCluster.PolicyArn)
		answer, err := message.BoolSelect("Proceed?")
		if err != nil {
			return fmt.Errorf("failed to select answer, %w", err)
		}
		if answer {
			_, err = iamClient.DetachRolePolicy(ctx, &iam.DetachRolePolicyInput{
				PolicyArn: &session.State.AwsProvider.ConnectCluster.PolicyArn,
				RoleName:  &session.State.AwsProvider.CreateCloudIdentity.RoleName,
			})
			if err != nil {
				return fmt.Errorf("failed to detach role policy, %w", err)
			}
			message.Info("Policy %s detached from role %s", session.State.AwsProvider.ConnectCluster.PolicyName, session.State.AwsProvider.CreateCloudIdentity.RoleName)
		} else {
			message.Info("Skipping detachment of the policy %s from role %s", session.State.AwsProvider.ConnectCluster.PolicyName, session.State.AwsProvider.CreateCloudIdentity.RoleName)
		}
	}

	if session.State.AwsProvider.CreateCloudIdentity.RoleName != "" {
		isRoleExists, err := a.isRoleExists(ctx, session.State.AwsProvider.CreateCloudIdentity.RoleName)
		if err != nil {
			return fmt.Errorf("failed to check if role exists, %w", err)
		}
		if !isRoleExists {
			message.Debug("AWS Role not found: %s, clearing state", session.State.AwsProvider.CreateCloudIdentity.RoleName)
			session.State.AwsProvider.CreateCloudIdentity.RoleName = ""
			if err := session.Save(); err != nil {
				return fmt.Errorf("failed to save state: %w", err)
			}
		} else {
			message.Info("Role will be deleted: aws iam delete-role --role-name %s", session.State.AwsProvider.CreateCloudIdentity.RoleName)
			answer, err := message.BoolSelect("Proceed?")
			if err != nil {
				return fmt.Errorf("failed to select answer, %w", err)
			}
			if answer {
				_, err = iamClient.DeleteRole(ctx, &iam.DeleteRoleInput{
					RoleName: &session.State.AwsProvider.CreateCloudIdentity.RoleName,
				})
				if err != nil {
					return fmt.Errorf("failed to delete role, %w", err)
				}
				message.Info("AWS Role deleted: %s", session.State.AwsProvider.CreateCloudIdentity.RoleName)
				session.State.AwsProvider.CreateCloudIdentity.RoleName = ""
				if err := session.Save(); err != nil {
					return fmt.Errorf("failed to save state: %w", err)
				}
			} else {
				message.Info("Skipping deletion of the role: %s", session.State.AwsProvider.CreateCloudIdentity.RoleName)
			}
		}
	}

	if session.State.AwsProvider.ConnectCluster.PolicyArn != "" {
		isPolicyExists, err := a.isPolicyExists(ctx, session.State.AwsProvider.ConnectCluster.PolicyArn)
		if err != nil {
			return fmt.Errorf("failed to check if policy exists, %w", err)
		}
		if !isPolicyExists {
			message.Debug("AWS Policy not found: %s, clearing state", session.State.AwsProvider.ConnectCluster.PolicyArn)
			session.State.AwsProvider.ConnectCluster.PolicyArn = ""
			if err := session.Save(); err != nil {
				return fmt.Errorf("failed to save state: %w", err)
			}
		} else {
			message.Info("Policy will be deleted: aws iam delete-policy --policy-arn %s", session.State.AwsProvider.ConnectCluster.PolicyArn)
			answer, err := message.BoolSelect("Proceed?")
			if err != nil {
				return fmt.Errorf("failed to select answer, %w", err)
			}
			if answer {
				_, err = iamClient.DeletePolicy(ctx, &iam.DeletePolicyInput{
					PolicyArn: &session.State.AwsProvider.ConnectCluster.PolicyArn,
				})
				if err != nil {
					return fmt.Errorf("failed to delete policy, %w", err)
				}
				message.Info("AWS Policy deleted: %s", session.State.AwsProvider.ConnectCluster.PolicyArn)
				session.State.AwsProvider.ConnectCluster.PolicyArn = ""
				if err := session.Save(); err != nil {
					return fmt.Errorf("failed to save state: %w", err)
				}
			} else {
				message.Info("Skipping deletion of the policy: %s", session.State.AwsProvider.ConnectCluster.PolicyArn)
			}
		}
	}

	return nil
}

func (a *awsProvider) getAccountId(ctx context.Context) (string, error) {
	stsClient := sts.NewFromConfig(a.awsConfig)
	caller, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("failed to get caller identity, %w", err)
	}
	if caller == nil || caller.Account == nil {
		return "", fmt.Errorf("failed to get caller identity: caller or caller.UserId is nil")
	}
	return *caller.Account, nil
}

func (a *awsProvider) isRoleExists(ctx context.Context, roleName string) (bool, error) {
	iamClient := iam.NewFromConfig(a.awsConfig)
	_, err := iamClient.GetRole(ctx, &iam.GetRoleInput{
		RoleName: &roleName,
	})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "NoSuchEntity" {
			return false, nil
		}
		return false, fmt.Errorf("failed to get role, %w", err)
	}
	return true, nil
}

func (a *awsProvider) isPolicyExists(ctx context.Context, policyArn string) (bool, error) {
	iamClient := iam.NewFromConfig(a.awsConfig)
	_, err := iamClient.GetPolicy(ctx, &iam.GetPolicyInput{
		PolicyArn: &policyArn,
	})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "NoSuchEntity" {
			return false, nil
		}
		return false, fmt.Errorf("failed to get policy, %w", err)
	}
	return true, nil
}

func (a *awsProvider) isPolicyAttachedToRole(ctx context.Context, roleName, policyArn string) (bool, error) {
	iamClient := iam.NewFromConfig(a.awsConfig)
	listPoliciesResp, err := iamClient.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
		RoleName: &roleName,
	})
	if err != nil {
		return false, fmt.Errorf("failed to list attached role policies, %w", err)
	}
	for _, attachedPolicy := range listPoliciesResp.AttachedPolicies {
		if *attachedPolicy.PolicyArn == policyArn {
			return true, nil
		}
	}
	return false, nil
}

func (a *awsProvider) isAccessEntryExists(ctx context.Context, clusterName, principalArn string) (bool, error) {
	eksClient := eks.NewFromConfig(a.awsConfig)
	_, err := eksClient.DescribeAccessEntry(ctx, &eks.DescribeAccessEntryInput{
		ClusterName:  &clusterName,
		PrincipalArn: &principalArn,
	})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "ResourceNotFoundException" {
			return false, nil
		}
		return false, fmt.Errorf("failed to describe access entry, %w", err)
	}
	return true, nil
}

func (a *awsProvider) isPodIdentityAssociationExists(ctx context.Context, clusterName, associationId string) (bool, error) {
	eksClient := eks.NewFromConfig(a.awsConfig)
	_, err := eksClient.DescribePodIdentityAssociation(ctx, &eks.DescribePodIdentityAssociationInput{
		AssociationId: &associationId,
		ClusterName:   &clusterName,
	})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "NotFoundException" {
			return false, nil
		}
		return false, fmt.Errorf("failed to describe pod identity association, %w", err)
	}
	return true, nil
}

func (a *awsProvider) isHumanitecResourceExists(ctx context.Context, resourceId string) (bool, error) {
	resp, err := a.humanitecPlatform.Client.GetResourceDefinitionWithResponse(ctx, a.humanitecPlatform.OrganizationId, resourceId, &client.GetResourceDefinitionParams{})
	if err != nil {
		return false, fmt.Errorf("failed to get resource definition, %w", err)
	}
	if resp.StatusCode() == 404 {
		return false, nil
	}
	if resp.StatusCode() != 200 {
		return false, fmt.Errorf("humanitec returned unexpected status code: %d with body %s", resp.StatusCode(), string(resp.Body))
	}
	return true, nil
}

func (a *awsProvider) isHumanitecSecretStoreResourceCreated(ctx context.Context, secretStoreId string) (bool, error) {
	resp, err := a.humanitecPlatform.Client.GetOrgsOrgIdSecretstoresStoreIdWithResponse(ctx, a.humanitecPlatform.OrganizationId, secretStoreId)
	if err != nil {
		return false, fmt.Errorf("failed to get secret store, %w", err)
	}
	if resp.StatusCode() == 404 {
		return false, nil
	}
	if resp.StatusCode() != 200 {
		return false, fmt.Errorf("humanitec returned unexpected status code: %d with body %s", resp.StatusCode(), string(resp.Body))
	}
	return true, nil
}

func generateAwsRoleName(prefix string) string {
	roleName := fmt.Sprintf("%s-%s", prefix, uuid.New().String())
	roleName = roleName[:min(len(roleName), 64)]
	roleName = strings.TrimSuffix(roleName, "-")
	return roleName
}

func generateAwsPolicyName(prefix string) string {
	roleName := fmt.Sprintf("%s-%s", prefix, uuid.New().String())
	roleName = roleName[:min(len(roleName), 128)]
	roleName = strings.TrimSuffix(roleName, "-")
	return roleName
}

func generateAwsK8sGroupName(prefix string) string {
	roleName := fmt.Sprintf("%s-%s", prefix, uuid.New().String())
	roleName = roleName[:min(len(roleName), 63)]
	roleName = strings.TrimSuffix(roleName, "-")
	return roleName
}

func generateKubeConfig(host, token string, certificate []byte) api.Config {
	clusters := make(map[string]*api.Cluster)
	clusters["cluster"] = &api.Cluster{
		Server:                   host,
		CertificateAuthorityData: certificate,
	}

	contexts := make(map[string]*api.Context)
	contexts["context"] = &api.Context{
		Cluster:  "cluster",
		AuthInfo: "authinfo",
	}

	authinfos := make(map[string]*api.AuthInfo)
	authinfos["authinfo"] = &api.AuthInfo{
		Token: token,
	}

	clientConfig := api.Config{
		Kind:           "Config",
		APIVersion:     "v1",
		Clusters:       clusters,
		Contexts:       contexts,
		CurrentContext: "context",
		AuthInfos:      authinfos,
	}

	return clientConfig
}

func (a *awsProvider) ensureK8sClient(ctx context.Context, clusterId string) error {
	if a.k8sClient != nil {
		return nil
	}

	kubeConfig, err := a.getKubeConfig(ctx, clusterId)
	if err != nil {
		return fmt.Errorf("failed to create kubeconfig: %w", err)
	}

	rawKubeConfig, err := clientcmd.Write(*kubeConfig)
	if err != nil {
		return fmt.Errorf("failed to create kubeconfig: %w", err)
	}

	clientConfig, err := clientcmd.NewClientConfigFromBytes(rawKubeConfig)
	if err != nil {
		return fmt.Errorf("failed to create k8s API client: %w", err)
	}

	config, err := clientConfig.ClientConfig()
	if err != nil {
		return fmt.Errorf("failed to create k8s API client: %w", err)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create k8s API client: %w", err)
	}

	a.k8sClient = client
	return nil
}
