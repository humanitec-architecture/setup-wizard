package cloud

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/humanitec/humanitec-go-autogen"
	"github.com/humanitec/humanitec-go-autogen/client"
	"github.com/humanitec/humctl-wizard/internal/message"
	"github.com/humanitec/humctl-wizard/internal/session"
	"github.com/humanitec/humctl-wizard/internal/utils"
	k8s_rbac "k8s.io/api/rbac/v1"
	k8s_apierrors "k8s.io/apimachinery/pkg/api/errors"
	k8s_meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8s_rbac_ac "k8s.io/client-go/applyconfigurations/rbac/v1"
	"k8s.io/client-go/kubernetes"
)

func checkResourceAccount(ctx context.Context, client *humanitec.Client, orgID, cloudAccountID string) error {
	resp, err := client.CheckResourceAccountWithResponse(ctx, orgID, cloudAccountID)
	if err != nil {
		return fmt.Errorf("failed to check Cloud Account '%s' with Humanitec: %w", cloudAccountID, err)
	}

	if resp.StatusCode() == http.StatusOK {
		if resp.JSON200.Warnings != nil {
			message.Info("check Cloud Account '%s' received some warnings: %v", cloudAccountID, *resp.JSON200.Warnings)
		}
		return nil
	}

	if resp.StatusCode() == http.StatusBadRequest {
		return fmt.Errorf("check Cloud Account '%s' with Humanitec unsuccessful. %s %s %v", cloudAccountID, resp.JSON400.Error, resp.JSON400.Message, resp.JSON400.Details)
	}
	return fmt.Errorf("failed to check Cloud Account '%s' with Humanitec: unexpected status code %d", cloudAccountID, resp.StatusCode())
}

func createResourceAccount(ctx context.Context, humClient *humanitec.Client, orgID string, req client.CreateResourceAccountRequestRequest) error {
	resp, err := humClient.CreateResourceAccountWithResponse(ctx, orgID,
		&client.CreateResourceAccountParams{
			CheckCredential: utils.Ref(true),
		}, req)
	if err != nil {
		return fmt.Errorf("failed to create Cloud Account '%s' in Humanitec: %w", req.Id, err)
	}
	if resp.StatusCode() == http.StatusOK {
		return nil
	}
	if resp.StatusCode() == http.StatusBadRequest {
		return fmt.Errorf("failed to create or test Cloud Account '%s' in Humanitec. Code: %s - message: %s - details: %v", req.Id, resp.JSON400.Error, resp.JSON400.Message, resp.JSON400.Details)
	}
	return fmt.Errorf("failed to create Cloud Account '%s' in Humanitec: unexpected status code %d instead of %d", req.Id, resp.StatusCode(), http.StatusOK)
}

func createResourceAccountWithRetries(ctx context.Context, client *humanitec.Client, orgID string, req client.CreateResourceAccountRequestRequest, timeout time.Duration) error {
	timeoutAfter := time.After(timeout)
	ticker := time.NewTicker(5 * time.Second)
	tick := ticker.C
	defer ticker.Stop()

	var err error
	for loop := true; loop; {
		select {
		case <-timeoutAfter:
			return fmt.Errorf("error creating resource account (retry timeout exceeded), %w", err)
		case <-tick:
			if err = createResourceAccount(ctx, client, orgID, req); err != nil {
				message.Debug("error creating resource account, retrying: %v", err)
				continue
			}
			loop = false
		}
	}
	return nil
}

func ensurek8sClusterRole(ctx context.Context, k8sClient *kubernetes.Clientset, roleName string) (bool, error) {
	if _, err := k8sClient.RbacV1().ClusterRoles().Get(ctx, roleName, k8s_meta.GetOptions{}); err != nil {
		if !k8s_apierrors.IsNotFound(err) {
			return false, fmt.Errorf("failed to check Cluster Role '%s' existence: %w", roleName, err)
		}
	} else {
		return true, nil
	}

	clusterRole := &k8s_rbac.ClusterRole{
		ObjectMeta: k8s_meta.ObjectMeta{
			Name: roleName,
		},
		Rules: []k8s_rbac.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"namespaces"},
				Verbs:     []string{"create", "get", "list", "update", "patch", "delete"},
			},
			{
				APIGroups: []string{"humanitec.io"},
				Resources: []string{"resources", "secretmappings", "workloadpatches", "workloads"},
				Verbs:     []string{"create", "get", "list", "update", "patch", "delete", "deletecollection", "watch"},
			},
			{
				APIGroups: []string{"batch"},
				Resources: []string{"jobs"},
				Verbs:     []string{"get", "list"},
			},
			{
				APIGroups: []string{"apps"},
				Resources: []string{"deployments", "statefulsets", "replicasets", "daemonsets"},
				Verbs:     []string{"get", "list"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get", "list"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"pods/log"},
				Verbs:     []string{"get", "list"},
			},
			{
				APIGroups: []string{"apps"},
				Resources: []string{"deployments/scale"},
				Verbs:     []string{"update"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"get"},
			},
		},
	}
	if _, err := k8sClient.RbacV1().ClusterRoles().Create(ctx, clusterRole, k8s_meta.CreateOptions{}); err != nil {
		return false, fmt.Errorf("failed to create Cluster Role '%s': %w", roleName, err)
	}

	return false, nil
}

func findExternalPrimarySecretStore(ctx context.Context, humClient *humanitec.Client, orgId, secretStoreId string) (bool, error) {
	resp, err := humClient.GetOrgsOrgIdSecretstoresStoreIdWithResponse(ctx, orgId, secretStoreId)
	if err != nil {
		return false, fmt.Errorf("failed to get Secret Store '%s' in Humanitec: %w", secretStoreId, err)
	}
	if resp.StatusCode() == http.StatusNotFound {
		return false, nil
	} else if resp.JSON200 != nil {
		return resp.JSON200.Primary, nil
	} else {
		return false, fmt.Errorf("failed to get Secret Store '%s' in Humanitec: unexpected status code %d instead of %d", secretStoreId, resp.StatusCode(), http.StatusOK)
	}
}

func ensureSecretStore(ctx context.Context, humClient *humanitec.Client, orgId, secretStoreId string, reqBody client.PostOrgsOrgIdSecretstoresJSONRequestBody) (bool, error) {
	resp, err := humClient.PostOrgsOrgIdSecretstoresWithResponse(ctx, orgId, reqBody)
	if err != nil {
		return false, fmt.Errorf("failed to create Secret Store '%s' in Humanitec: %w", secretStoreId, err)
	}
	if resp.StatusCode() == http.StatusCreated {
		return false, nil
	} else if resp.StatusCode() == http.StatusConflict {
		return true, nil
	} else {
		return false, fmt.Errorf("failed to create Secret Store '%s' in Humanitec: unexpected status code %d instead of %d", secretStoreId, resp.StatusCode(), http.StatusCreated)
	}
}

func listLoadBalancers(ctx context.Context, clientset *kubernetes.Clientset) ([]string, error) {
	session.State.Application.Connect.LoadBalancers = make(map[string]string)
	list, err := clientset.CoreV1().Services("").List(ctx, k8s_meta.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list load balancers: %w", err)
	}
	outputs := make([]string, 0)
	for _, service := range list.Items {
		if service.Spec.Type == "LoadBalancer" {
			if len(service.Status.LoadBalancer.Ingress) > 0 {
				if service.Status.LoadBalancer.Ingress[0].IP != "" {
					session.State.Application.Connect.LoadBalancers[service.Name+"."+service.Namespace] = service.Status.LoadBalancer.Ingress[0].IP
				} else if service.Status.LoadBalancer.Ingress[0].Hostname != "" {
					session.State.Application.Connect.LoadBalancers[service.Name+"."+service.Namespace] = service.Status.LoadBalancer.Ingress[0].Hostname
				}
			}
			outputs = append(outputs, service.Name+"."+service.Namespace)
		}
	}
	return outputs, nil
}

func createClusterRoleAndBinding(ctx context.Context, clientset *kubernetes.Clientset, rbacSubject k8s_rbac.Subject, k8sSession *session.K8s) error {
	if k8sSession == nil {
		return errors.New("k8s session is nil")
	}
	var clusterRoleName string
	if savedClusterRole := k8sSession.ClusterRoleName; savedClusterRole != "" {
		clusterRoleName = savedClusterRole
	} else {
		clusterRoleName = K8sClusterRoleBaseName
	}

	if alreadyExists, err := ensurek8sClusterRole(ctx, clientset, clusterRoleName); err != nil {
		return fmt.Errorf("failed to ensure Cluster Role '%s' exists: %w", clusterRoleName, err)
	} else if alreadyExists {
		message.Info("Kubernetes Cluster Role '%s' already exists", clusterRoleName)
	} else {
		message.Info("Kubernetes Cluster Role '%s' created", clusterRoleName)
		if err = session.Save(); err != nil {
			return fmt.Errorf("failed to save state: %w", err)
		}
	}
	k8sSession.ClusterRoleName = clusterRoleName

	clusterRoleBindingName := K8sClusterRoleBindingBaseName
	if savedClusterRoleBindingName := k8sSession.ClusterRoleBindingName; savedClusterRoleBindingName != "" {
		clusterRoleBindingName = savedClusterRoleBindingName
	}

	clusterRoleBinding := k8s_rbac_ac.ClusterRoleBinding(clusterRoleBindingName).
		WithSubjects(&k8s_rbac_ac.SubjectApplyConfiguration{
			Kind:      &rbacSubject.Kind,
			APIGroup:  &rbacSubject.APIGroup,
			Name:      &rbacSubject.Name,
			Namespace: &rbacSubject.Namespace,
		}).
		WithRoleRef(&k8s_rbac_ac.RoleRefApplyConfiguration{
			APIGroup: to.Ptr("rbac.authorization.k8s.io"),
			Kind:     to.Ptr("ClusterRole"),
			Name:     &k8sSession.ClusterRoleName,
		})

	if _, err := clientset.RbacV1().ClusterRoleBindings().Apply(ctx, clusterRoleBinding, k8s_meta.ApplyOptions{
		FieldManager: "humctl-wizard",
	}); err != nil {
		return fmt.Errorf("failed to create Kubernetes Custom Role Binding '%s': %w", clusterRoleBindingName, err)
	}
	message.Info("Kubernetes Cluster Role Binding '%s' created", clusterRoleBindingName)
	k8sSession.ClusterRoleBindingName = clusterRoleBindingName

	return nil
}
