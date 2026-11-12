/*
Copyright The Platform Mesh Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package subroutines

import (
	"context"
	"fmt"
	"time"

	pmcorev1alpha1 "go.platform-mesh.io/apis/core/v1alpha1"
	"go.platform-mesh.io/golang-commons/logger"
	"go.platform-mesh.io/platform-mesh-operator/internal/config"
	"go.platform-mesh.io/platform-mesh-operator/internal/metrics"
	"go.platform-mesh.io/subroutines"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func NewWaitSubroutine(
	client ctrlruntimeclient.Client,
	clientRuntime ctrlruntimeclient.Client,
	cfg *config.OperatorConfig,
	helper KcpHelper,
	kcpUrl string,
) *WaitSubroutine {
	return &WaitSubroutine{
		client:        client,
		clientRuntime: clientRuntime,
		cfg:           cfg,
		kcpHelper:     helper,
		kcpUrl:        kcpUrl,
	}
}

type WaitSubroutine struct {
	client        ctrlruntimeclient.Client // infra cluster — resource readiness checks
	clientRuntime ctrlruntimeclient.Client // runtime cluster — KCP secret access
	cfg           *config.OperatorConfig
	kcpHelper     KcpHelper
	kcpUrl        string
}

const (
	WaitSubroutineName = "WaitSubroutine"
)

func (r *WaitSubroutine) Finalize(
	_ context.Context, _ ctrlruntimeclient.Object,
) (subroutines.Result, error) {
	return subroutines.OK(), nil
}

func (r *WaitSubroutine) Process(
	ctx context.Context, runtimeObj ctrlruntimeclient.Object,
) (res subroutines.Result, err error) {
	start := time.Now()
	defer func() {
		labelResult := "success"
		if err != nil {
			labelResult = "error"
		}
		metrics.SubroutineTotal.WithLabelValues(r.GetName(), labelResult).Inc()
		metrics.SubroutineDuration.WithLabelValues(r.GetName()).Observe(time.Since(start).Seconds())
	}()
	instance := runtimeObj.(*pmcorev1alpha1.PlatformMesh)
	log := logger.LoadLoggerFromContext(ctx).ChildLogger("subroutine", r.GetName())

	waitConfig := DEFAULT_WAIT_CONFIG
	if instance.Spec.Wait != nil {
		log.Info().Msg("Using custom WaitConfig")
		waitConfig = *instance.Spec.Wait
	} else {
		log.Info().Msg("No WaitConfig specified, using defaults")
	}

	for _, resourceType := range waitConfig.ResourceTypes {
		log.Info().Msgf("Waiting for resource type: %s", resourceType)

		if resourceType.Name != "" {
			res := &unstructured.Unstructured{}
			res.SetGroupVersionKind(schema.GroupVersionKind{
				Group:   resourceType.Group,
				Version: resourceType.Version,
				Kind:    resourceType.Kind,
			})
			err := r.client.Get(ctx, ctrlruntimeclient.ObjectKey{
				Namespace: resourceType.Namespace,
				Name:      resourceType.Name,
			}, res)
			if err != nil {
				log.Info().Msgf("Error getting resource %s/%s: %v", resourceType.Namespace, resourceType.Name, err)
				return subroutines.StopWithRequeue(DefaultRequeueInterval, "get resource"), nil
			}
			if !matchesConditionWithStatus(res, string(resourceType.RowConditionType), string(resourceType.ConditionStatus)) {
				log.Info().Msgf("Resource %s/%s of type %s is not ready yet", resourceType.Namespace, resourceType.Name, res.GetKind())
				return subroutines.StopWithRequeue(DefaultRequeueInterval, fmt.Sprintf("resource %s/%s of type %s is not ready yet", resourceType.Namespace, resourceType.Name, res.GetKind())), nil
			}
			continue
		}

		// use LabelSelector if no Name is specified
		waitList := &unstructured.UnstructuredList{}
		waitList.SetGroupVersionKind(schema.GroupVersionKind{
			Group:   resourceType.Group,
			Version: resourceType.Version,
			Kind:    resourceType.Kind,
		})
		ls, err := metav1.LabelSelectorAsSelector(&resourceType.LabelSelector)
		if err != nil {
			log.Info().Msgf("Error converting label selector: %v", err)
			return subroutines.StopWithRequeue(DefaultRequeueInterval, "label selector"), nil
		}
		if err := r.client.List(ctx, waitList, &ctrlruntimeclient.ListOptions{
			Namespace:     resourceType.Namespace,
			LabelSelector: ls,
		}); err != nil {
			log.Info().Msgf("Error listing resources: %v", err)
			return subroutines.StopWithRequeue(DefaultRequeueInterval, "list resources"), nil
		}

		for _, item := range waitList.Items {
			if !matchesConditionWithStatus(&item, string(resourceType.RowConditionType), string(resourceType.ConditionStatus)) {
				log.Info().Msgf("Resource %s/%s of type %s is not ready yet", item.GetNamespace(), item.GetName(), item.GetKind())
				return subroutines.StopWithRequeue(DefaultRequeueInterval, fmt.Sprintf("resource %s/%s of type %s is not ready yet", item.GetNamespace(), item.GetName(), item.GetKind())), nil
			}
		}
	}

	// Headless compositions can omit the initializer that supplies this audience.
	if !r.cfg.Subroutines.Wait.WorkspaceAuthDisabled {
		if err := r.checkWorkspaceAuthConfigAudience(ctx, log, instance); err != nil {
			return subroutines.StopWithRequeue(DefaultRequeueInterval, err.Error()), nil
		}
	}

	return subroutines.OK(), nil
}

func (r *WaitSubroutine) checkWorkspaceAuthConfigAudience(ctx context.Context, log *logger.Logger, inst *pmcorev1alpha1.PlatformMesh) error {
	kubeCfg, err := BuildKubeconfigFromConfig(r.clientRuntime, &r.cfg.KCP, getExternalKcpHost(inst, r.cfg))
	if err != nil {
		log.Debug().Err(err).Msg("Failed to build kubeconfig, skipping WorkspaceAuthenticationConfiguration check")
		return nil
	}

	orgsClient, err := r.kcpHelper.NewKcpClient(kubeCfg, "root")
	if err != nil {
		log.Debug().Err(err).Msg("Failed to create KCP client for root workspace, skipping")
		return nil
	}

	wac := &unstructured.Unstructured{}
	wac.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "tenancy.kcp.io",
		Version: "v1alpha1",
		Kind:    "WorkspaceAuthenticationConfiguration",
	})

	if err = orgsClient.Get(ctx, types.NamespacedName{Name: "orgs-authentication"}, wac); err != nil {
		log.Debug().Err(err).Msg("Failed to get WorkspaceAuthenticationConfiguration, skipping")
		return nil
	}

	jwtConfigs, found, err := unstructured.NestedSlice(wac.Object, "spec", "jwt")
	if err != nil || !found || len(jwtConfigs) == 0 {
		return nil //nolint:nilerr
	}
	jwt, ok := jwtConfigs[0].(map[string]any)
	if !ok {
		return nil
	}
	issuer, ok := jwt["issuer"].(map[string]any)
	if !ok {
		return nil
	}
	audiences, ok, _ := unstructured.NestedStringSlice(issuer, "audiences")
	if !ok {
		return nil
	}

	if len(audiences) == 0 {
		log.Info().Msg("WorkspaceAuthenticationConfiguration audiences is not yet set, triggering reconcile")
		return fmt.Errorf("WorkspaceAuthenticationConfiguration audience is not yet set")
	}

	if len(audiences) == 1 {
		if audiences[0] == "<placeholder>" {
			return fmt.Errorf("audiences is set to \"<placeholder>\"")
		}
	}

	return nil
}

func (r *WaitSubroutine) Finalizers(_ ctrlruntimeclient.Object) []string { // coverage-ignore
	return []string{}
}

func (r *WaitSubroutine) GetName() string {
	return WaitSubroutineName
}
