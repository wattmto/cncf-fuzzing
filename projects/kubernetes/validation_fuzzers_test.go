// Copyright 2021 ADA Logics Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package fuzzing

import (
	"context"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"testing"

	v1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsValidation "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/apis/audit"
	auditValidation "k8s.io/apiserver/pkg/apis/audit/validation"
	"k8s.io/kubernetes/pkg/apis/apiserverinternal"
	apiServerInternalValidation "k8s.io/kubernetes/pkg/apis/apiserverinternal/validation"
	"k8s.io/kubernetes/pkg/apis/apps"
	appsValidation "k8s.io/kubernetes/pkg/apis/apps/validation"
	"k8s.io/kubernetes/pkg/apis/autoscaling"
	autoscalingValidation "k8s.io/kubernetes/pkg/apis/autoscaling/validation"
	"k8s.io/kubernetes/pkg/apis/batch"
	batchValidation "k8s.io/kubernetes/pkg/apis/batch/validation"
	"k8s.io/kubernetes/pkg/apis/certificates"
	certificatesValidation "k8s.io/kubernetes/pkg/apis/certificates/validation"
	"k8s.io/kubernetes/pkg/apis/core"
	k8s_api_v1 "k8s.io/kubernetes/pkg/apis/core/v1"
	"k8s.io/kubernetes/pkg/apis/core/validation"
	"k8s.io/kubernetes/pkg/apis/policy"
	policyValidation "k8s.io/kubernetes/pkg/apis/policy/validation"
	"k8s.io/kubernetes/pkg/apis/rbac"
	rbacValidation "k8s.io/kubernetes/pkg/apis/rbac/validation"
	rbacregistryvalidation "k8s.io/kubernetes/pkg/registry/rbac/validation"
)

const maxFuzzers = 50

func FuzzAllValidation(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 10 {
			return
		}
		op := int(data[0]) % maxFuzzers
		inputData := data[1:]
		if op == 0 {
			fuzzValidatePodCreate(inputData)
		} else if op == 1 {
			fuzzValidatePodUpdate(inputData)
		} else if op == 2 {
			fuzzValidatePodStatusUpdate(inputData)
		} else if op == 3 {
			fuzzValidatePodEphemeralContainersUpdate(inputData)
		} else if op == 4 {
			fuzzValidatePersistentVolumeUpdate(inputData)
		} else if op == 5 {
			fuzzValidatePersistentVolumeClaimUpdate(inputData)
		} else if op == 6 {
			fuzzValidateServiceCreate(inputData)
		} else if op == 7 {
			fuzzValidateServiceUpdate(inputData)
		} else if op == 8 {
			fuzzValidateEndpointsCreate(inputData)
		} else if op == 9 {
			fuzzValidateNodeUpdate(inputData)
		} else if op == 10 {
			fuzzValidateLimitRange(inputData)
		} else if op == 11 {
			fuzzValidateStatefulSet(inputData)
		} else if op == 12 {
			fuzzValidateStatefulSetUpdate(inputData)
		} else if op == 13 {
			fuzzValidateDaemonSet(inputData)
		} else if op == 14 {
			fuzzValidateDaemonSetUpdate(inputData)
		} else if op == 15 {
			fuzzValidateDeployment(inputData)
		} else if op == 16 {
			fuzzValidateDeploymentUpdate(inputData)
		} else if op == 17 {
			fuzzValidateJob(inputData)
		} else if op == 18 {
			fuzzValidateJobUpdate(inputData)
		} else if op == 19 {
			fuzzValidateCronJobCreate(inputData)
		} else if op == 20 {
			fuzzValidateCronJobUpdate(inputData)
		} else if op == 21 {
			fuzzValidateScale(inputData)
		} else if op == 22 {
			fuzzValidateHorizontalPodAutoscaler(inputData)
		} else if op == 23 {
			fuzzValidateHorizontalPodAutoscalerUpdate(inputData)
		} else if op == 24 {
			fuzzValidateDeployment(inputData)
		} else if op == 25 {
			fuzzValidatePodDisruptionBudget(inputData)
		} else if op == 26 {
			fuzzValidatePodDisruptionBudgetStatusUpdate(inputData)
		} else if op == 31 {
			fuzzValidateCertificateSigningRequestCreate(inputData)
		} else if op == 32 {
			fuzzValidateCertificateSigningRequestUpdate(inputData)
		} else if op == 33 {
			fuzzValidateCertificateSigningRequestStatusUpdate(inputData)
		} else if op == 34 {
			fuzzValidateCertificateSigningRequestApprovalUpdate(inputData)
		} else if op == 35 {
			fuzzValidateCustomResourceDefinition(inputData)
		} else if op == 36 {
			fuzzValidateStorageVersion(inputData)
		} else if op == 37 {
			fuzzValidateStorageVersionName(inputData)
		} else if op == 38 {
			fuzzValidateStorageVersionStatusUpdate(inputData)
		} else if op == 39 {
			fuzzValidatePolicy(inputData)
		} else if op == 40 {
			FuzzLoadPolicyFromBytes(inputData)
		} else if op == 41 {
			fuzzValidateRoleUpdate(inputData)
		} else if op == 42 {
			fuzzValidateClusterRoleUpdate(inputData)
		} else if op == 43 {
			fuzzValidateRoleBindingUpdate(inputData)
		} else if op == 44 {
			fuzzValidateClusterRoleBindingUpdate(inputData)
		} else if op == 45 {
			fuzzCompactRules(inputData)
		} else if op == 46 {
			fuzzValidateResourceQuotaSpec(inputData)
		} else if op == 47 {
			fuzzValidateResourceQuotaUpdate(inputData)
		} else if op == 48 {
			fuzzValidateResourceQuotaStatusUpdate(inputData)
		} else if op == 49 {
			fuzzValidateServiceStatusUpdate(inputData)
		}
		return
	})
}

//// Pod validation

func fuzzValidatePodCreate(data []byte) {
	f := fuzz.NewConsumer(data)
	pod := &core.Pod{}
	err := f.GenerateStruct(pod)
	if err != nil {
		return
	}
	if errs := validation.ValidatePodCreate(pod, validation.PodValidationOptions{}); len(errs) > 0 {
		return
	}

	// Now test conversion
	v1Pod := &v1.Pod{}
	_ = k8s_api_v1.Convert_core_Pod_To_v1_Pod(pod, v1Pod, nil)
	return
}

func fuzzValidatePodUpdate(data []byte) {
	f := fuzz.NewConsumer(data)
	pod1 := &core.Pod{}
	err := f.GenerateStruct(pod1)
	if err != nil {
		return
	}
	pod2 := &core.Pod{}
	err = f.GenerateStruct(pod2)
	if err != nil {
		return
	}
	_ = validation.ValidatePodUpdate(pod1, pod2, validation.PodValidationOptions{})
	return
}

func fuzzValidatePodStatusUpdate(data []byte) {
	f := fuzz.NewConsumer(data)
	pod1 := &core.Pod{}
	err := f.GenerateStruct(pod1)
	if err != nil {
		return
	}
	pod2 := &core.Pod{}
	err = f.GenerateStruct(pod2)
	if err != nil {
		return
	}
	_ = validation.ValidatePodStatusUpdate(pod1, pod2, validation.PodValidationOptions{})
	return
}

func fuzzValidatePodEphemeralContainersUpdate(data []byte) {
	f := fuzz.NewConsumer(data)
	pod1 := &core.Pod{}
	err := f.GenerateStruct(pod1)
	if err != nil {
		return
	}
	pod2 := &core.Pod{}
	err = f.GenerateStruct(pod2)
	if err != nil {
		return
	}
	_ = validation.ValidatePodEphemeralContainersUpdate(pod1, pod2, validation.PodValidationOptions{})
	return
}

// Persistent volume validation

func fuzzValidatePersistentVolumeUpdate(data []byte) {
	f := fuzz.NewConsumer(data)
	pv1 := &core.PersistentVolume{}
	err := f.GenerateStruct(pv1)
	if err != nil {
		return
	}
	pv2 := &core.PersistentVolume{}
	err = f.GenerateStruct(pv2)
	if err != nil {
		return
	}
	opts := validation.PersistentVolumeSpecValidationOptions{}
	_ = validation.ValidatePersistentVolumeUpdate(pv1, pv2, opts)
	return
}

// Persistent Volume clain validation

func fuzzValidatePersistentVolumeClaimUpdate(data []byte) {
	f := fuzz.NewConsumer(data)
	pvc1 := &core.PersistentVolumeClaim{}
	err := f.GenerateStruct(pvc1)
	if err != nil {
		return
	}
	pvc2 := &core.PersistentVolumeClaim{}
	err = f.GenerateStruct(pvc2)
	if err != nil {
		return
	}
	opts := validation.PersistentVolumeClaimSpecValidationOptions{}
	_ = validation.ValidatePersistentVolumeClaimUpdate(pvc1, pvc2, opts)
	return
}

//// Service validation

func fuzzValidateServiceCreate(data []byte) {
	service := &core.Service{}
	f := fuzz.NewConsumer(data)
	err := f.GenerateStruct(service)
	if err != nil {
		return
	}
	_ = validation.ValidateServiceCreate(service)
	return
}

func fuzzValidateServiceUpdate(data []byte) {
	service1 := &core.Service{}
	f := fuzz.NewConsumer(data)
	err := f.GenerateStruct(service1)
	if err != nil {
		return
	}
	service2 := &core.Service{}
	err = f.GenerateStruct(service2)
	if err != nil {
		return
	}
	_ = validation.ValidateServiceUpdate(service1, service2)
	return
}

//// Endpoints validation

func fuzzValidateEndpointsCreate(data []byte) {
	endpoints := &core.Endpoints{}
	f := fuzz.NewConsumer(data)
	err := f.GenerateStruct(endpoints)
	if err != nil {
		return
	}
	_ = validation.ValidateEndpointsCreate(endpoints)
	return
}

// Node validation

func fuzzValidateNodeUpdate(data []byte) {
	node1 := &core.Node{}
	f := fuzz.NewConsumer(data)
	err := f.GenerateStruct(node1)
	if err != nil {
		return
	}
	node2 := &core.Node{}
	err = f.GenerateStruct(node2)
	if err != nil {
		return
	}
	_ = validation.ValidateNodeUpdate(node1, node2)
	return
}

// Limit Range validation

func fuzzValidateLimitRange(data []byte) {
	limitRange := &core.LimitRange{}
	f := fuzz.NewConsumer(data)
	err := f.GenerateStruct(limitRange)
	if err != nil {
		return
	}
	_ = validation.ValidateLimitRange(limitRange)
	return
}

// apps validation

func fuzzValidateStatefulSet(data []byte) {
	statefulset := &apps.StatefulSet{}
	f := fuzz.NewConsumer(data)
	err := f.GenerateStruct(statefulset)
	if err != nil {
		return
	}
	if errs := appsValidation.ValidateStatefulSet(statefulset, validation.PodValidationOptions{}); len(errs) > 0 {
		return
	}
	return
}

func fuzzValidateStatefulSetUpdate(data []byte) {
	f := fuzz.NewConsumer(data)
	statefulset1 := &apps.StatefulSet{}
	err := f.GenerateStruct(statefulset1)
	if err != nil {
		return
	}
	statefulset2 := &apps.StatefulSet{}
	err = f.GenerateStruct(statefulset2)
	if err != nil {
		return
	}
	opts := validation.PodValidationOptions{}
	err = f.GenerateStruct(&opts)
	if err != nil {
		return
	}
	if errs := appsValidation.ValidateStatefulSetUpdate(statefulset1, statefulset2, opts); len(errs) > 0 {
		return
	}
	return
}

func fuzzValidateDaemonSet(data []byte) {
	daemonset := &apps.DaemonSet{}
	f := fuzz.NewConsumer(data)
	err := f.GenerateStruct(daemonset)
	if err != nil {
		return
	}
	if errs := appsValidation.ValidateDaemonSet(daemonset, validation.PodValidationOptions{}); len(errs) > 0 {
		return
	}
	return
}

func fuzzValidateDaemonSetUpdate(data []byte) int {
	//fmt.Println("Calling fuzzValidateDaemonSetUpdate")
	f := fuzz.NewConsumer(data)
	daemonset1 := &apps.DaemonSet{}
	err := f.GenerateStruct(daemonset1)
	if err != nil {
		return 0
	}
	daemonset2 := &apps.DaemonSet{}
	err = f.GenerateStruct(daemonset2)
	if err != nil {
		return 0
	}
	if errs := appsValidation.ValidateDaemonSetUpdate(daemonset1, daemonset2, validation.PodValidationOptions{}); len(errs) > 0 {
		for _, err := range errs {
			_ = err
			//fmt.Println(err)
		}
		return 0
	}
	return 1
}

func fuzzValidateDeployment(data []byte) {
	deployment := &apps.Deployment{}
	f := fuzz.NewConsumer(data)
	err := f.GenerateStruct(deployment)
	if err != nil {
		return
	}
	if errs := appsValidation.ValidateDeployment(deployment, validation.PodValidationOptions{}); len(errs) > 0 {
		return
	}
	return
}

func fuzzValidateDeploymentUpdate(data []byte) {
	f := fuzz.NewConsumer(data)
	deployment1 := &apps.Deployment{}
	err := f.GenerateStruct(deployment1)
	if err != nil {
		return
	}
	deployment2 := &apps.Deployment{}
	err = f.GenerateStruct(deployment2)
	if err != nil {
		return
	}
	if errs := appsValidation.ValidateDeploymentUpdate(deployment1, deployment2, validation.PodValidationOptions{}); len(errs) > 0 {
		return
	}
	return
}

// batch validation

func fuzzValidateJob(data []byte) {
	f := fuzz.NewConsumer(data)
	job := &batch.Job{}
	err := f.GenerateStruct(job)
	if err != nil {
		return
	}
	if errs := batchValidation.ValidateJob(job, batchValidation.JobValidationOptions{}); len(errs) > 0 {
		return
	}
	return
}

func fuzzValidateJobUpdate(data []byte) {
	f := fuzz.NewConsumer(data)
	job1 := &batch.Job{}
	err := f.GenerateStruct(job1)
	if err != nil {
		return
	}
	job2 := &batch.Job{}
	err = f.GenerateStruct(job2)
	if err != nil {
		return
	}
	if errs := batchValidation.ValidateJobUpdate(job1, job2, batchValidation.JobValidationOptions{}); len(errs) > 0 {
		return
	}
	return
}

func fuzzValidateCronJobCreate(data []byte) {
	f := fuzz.NewConsumer(data)
	cronjob := &batch.CronJob{}
	err := f.GenerateStruct(cronjob)
	if err != nil {
		return
	}
	if errs := batchValidation.ValidateCronJobCreate(cronjob, validation.PodValidationOptions{}); len(errs) > 0 {
		return
	}
	return
}

func fuzzValidateCronJobUpdate(data []byte) {
	f := fuzz.NewConsumer(data)
	cronjob1 := &batch.CronJob{}
	err := f.GenerateStruct(cronjob1)
	if err != nil {
		return
	}
	cronjob2 := &batch.CronJob{}
	err = f.GenerateStruct(cronjob2)
	if err != nil {
		return
	}
	if errs := batchValidation.ValidateCronJobUpdate(cronjob1, cronjob2, validation.PodValidationOptions{}); len(errs) > 0 {
		return
	}
	return
}

// autoscaling validation

func fuzzValidateScale(data []byte) {
	f := fuzz.NewConsumer(data)
	scale := &autoscaling.Scale{}
	err := f.GenerateStruct(scale)
	if err != nil {
		return
	}
	if errs := autoscalingValidation.ValidateScale(scale); len(errs) > 0 {
		return
	}
	return
}

func fuzzValidateHorizontalPodAutoscaler(data []byte) {
	f := fuzz.NewConsumer(data)
	autoscaler := &autoscaling.HorizontalPodAutoscaler{}
	err := f.GenerateStruct(autoscaler)
	if err != nil {
		return
	}
	if errs := autoscalingValidation.ValidateHorizontalPodAutoscaler(autoscaler); len(errs) > 0 {
		return
	}
	return
}

func fuzzValidateHorizontalPodAutoscalerUpdate(data []byte) {
	f := fuzz.NewConsumer(data)
	autoscaler1 := &autoscaling.HorizontalPodAutoscaler{}
	err := f.GenerateStruct(autoscaler1)
	if err != nil {
		return
	}
	autoscaler2 := &autoscaling.HorizontalPodAutoscaler{}
	err = f.GenerateStruct(autoscaler2)
	if err != nil {
		return
	}
	if errs := autoscalingValidation.ValidateHorizontalPodAutoscalerUpdate(autoscaler1, autoscaler2); len(errs) > 0 {
		return
	}
	return
}

// policy validation

func fuzzValidatePodDisruptionBudget(data []byte) {
	f := fuzz.NewConsumer(data)
	pdb := &policy.PodDisruptionBudget{}
	err := f.GenerateStruct(pdb)
	if err != nil {
		return
	}
	if errs := policyValidation.ValidatePodDisruptionBudget(pdb, policyValidation.PodDisruptionBudgetValidationOptions{}); len(errs) > 0 {
		return
	}
	return
}

func fuzzValidatePodDisruptionBudgetStatusUpdate(data []byte) {
	f := fuzz.NewConsumer(data)
	status := policy.PodDisruptionBudgetStatus{}
	err := f.GenerateStruct(&status)
	if err != nil {
		return
	}
	oldStatus := policy.PodDisruptionBudgetStatus{}
	err = f.GenerateStruct(&oldStatus)
	if err != nil {
		return
	}
	if errs := policyValidation.ValidatePodDisruptionBudgetStatusUpdate(status, oldStatus, field.NewPath("status"), policy.SchemeGroupVersion); len(errs) > 0 {
		return
	}
	if errs := policyValidation.ValidatePodDisruptionBudgetStatusUpdate(status, oldStatus, field.NewPath("status"), policyv1beta1.SchemeGroupVersion); len(errs) > 0 {
		return
	}
	return
}

// certificates

func fuzzValidateCertificateSigningRequestCreate(data []byte) {
	f := fuzz.NewConsumer(data)
	csr := &certificates.CertificateSigningRequest{}
	err := f.GenerateStruct(csr)
	if err != nil {
		return
	}
	if errs := certificatesValidation.ValidateCertificateSigningRequestCreate(csr); len(errs) > 0 {
		return
	}
	return
}

func fuzzValidateCertificateSigningRequestUpdate(data []byte) {
	f := fuzz.NewConsumer(data)
	csr1 := &certificates.CertificateSigningRequest{}
	err := f.GenerateStruct(csr1)
	if err != nil {
		return
	}
	csr2 := &certificates.CertificateSigningRequest{}
	err = f.GenerateStruct(csr2)
	if err != nil {
		return
	}
	if errs := certificatesValidation.ValidateCertificateSigningRequestUpdate(csr1, csr2); len(errs) > 0 {
		return
	}
	return
}

func fuzzValidateCertificateSigningRequestStatusUpdate(data []byte) {
	f := fuzz.NewConsumer(data)
	csr1 := &certificates.CertificateSigningRequest{}
	err := f.GenerateStruct(csr1)
	if err != nil {
		return
	}
	csr2 := &certificates.CertificateSigningRequest{}
	err = f.GenerateStruct(csr2)
	if err != nil {
		return
	}
	if errs := certificatesValidation.ValidateCertificateSigningRequestStatusUpdate(csr1, csr2); len(errs) > 0 {
		return
	}
	return
}

func fuzzValidateCertificateSigningRequestApprovalUpdate(data []byte) {
	f := fuzz.NewConsumer(data)
	csr1 := &certificates.CertificateSigningRequest{}
	err := f.GenerateStruct(csr1)
	if err != nil {
		return
	}
	csr2 := &certificates.CertificateSigningRequest{}
	err = f.GenerateStruct(csr1)
	if err != nil {
		return
	}
	if errs := certificatesValidation.ValidateCertificateSigningRequestApprovalUpdate(csr1, csr2); len(errs) > 0 {
		return
	}
	return
}

// apiextensions-apiserver
func fuzzValidateCustomResourceDefinition(data []byte) {
	f := fuzz.NewConsumer(data)
	crd := &apiextensions.CustomResourceDefinition{}
	err := f.GenerateStruct(crd)
	if err != nil {
		return
	}
	if errs := apiextensionsValidation.ValidateCustomResourceDefinition(context.Background(), crd); len(errs) > 0 {
		return
	}
	return
}

// apiserverinternal

func fuzzValidateStorageVersion(data []byte) {
	f := fuzz.NewConsumer(data)
	sv := &apiserverinternal.StorageVersion{}
	err := f.GenerateStruct(sv)
	if err != nil {
		return
	}
	if errs := apiServerInternalValidation.ValidateStorageVersion(sv); len(errs) > 0 {
		return
	}
	return
}

func fuzzValidateStorageVersionName(data []byte) {
	if errs := apiServerInternalValidation.ValidateStorageVersionName(string(data), false); len(errs) > 0 {
		return
	}
	return
}

func fuzzValidateStorageVersionStatusUpdate(data []byte) {
	f := fuzz.NewConsumer(data)
	sv1 := &apiserverinternal.StorageVersion{}
	err := f.GenerateStruct(sv1)
	if err != nil {
		return
	}
	sv2 := &apiserverinternal.StorageVersion{}
	err = f.GenerateStruct(sv2)
	if err != nil {
		return
	}
	if errs := apiServerInternalValidation.ValidateStorageVersionStatusUpdate(sv1, sv2); len(errs) > 0 {
		return
	}
	return
}

// apiserver audit

func fuzzValidatePolicy(data []byte) {
	f := fuzz.NewConsumer(data)
	p := &audit.Policy{}
	err := f.GenerateStruct(p)
	if err != nil {
		return
	}
	if errs := auditValidation.ValidatePolicy(p); len(errs) > 0 {
		return
	}
	return
}

// rbac validation
func fuzzValidateRoleUpdate(data []byte) {
	f := fuzz.NewConsumer(data)
	role1 := &rbac.Role{}
	err := f.GenerateStruct(role1)
	if err != nil {
		return
	}
	role2 := &rbac.Role{}
	err = f.GenerateStruct(role2)
	if err != nil {
		return
	}
	if errs := rbacValidation.ValidateRoleUpdate(role1, role2); len(errs) > 0 {
		return
	}
	return
}

func fuzzValidateClusterRoleUpdate(data []byte) {
	f := fuzz.NewConsumer(data)
	clusterRole1 := &rbac.ClusterRole{}
	err := f.GenerateStruct(clusterRole1)
	if err != nil {
		return
	}
	clusterRole2 := &rbac.ClusterRole{}
	err = f.GenerateStruct(clusterRole2)
	if err != nil {
		return
	}
	if errs := rbacValidation.ValidateClusterRoleUpdate(clusterRole1, clusterRole2, rbacValidation.ClusterRoleValidationOptions{}); len(errs) > 0 {
		return
	}
	return
}

func fuzzValidateRoleBindingUpdate(data []byte) {
	f := fuzz.NewConsumer(data)
	roleBinding1 := &rbac.RoleBinding{}
	err := f.GenerateStruct(roleBinding1)
	if err != nil {
		return
	}
	roleBinding2 := &rbac.RoleBinding{}
	err = f.GenerateStruct(roleBinding2)
	if err != nil {
		return
	}
	if errs := rbacValidation.ValidateRoleBindingUpdate(roleBinding1, roleBinding2); len(errs) > 0 {
		return
	}
	return
}

func fuzzValidateClusterRoleBindingUpdate(data []byte) {
	f := fuzz.NewConsumer(data)
	clusterRoleBinding1 := &rbac.ClusterRoleBinding{}
	err := f.GenerateStruct(clusterRoleBinding1)
	if err != nil {
		return
	}
	clusterRoleBinding2 := &rbac.ClusterRoleBinding{}
	err = f.GenerateStruct(clusterRoleBinding2)
	if err != nil {
		return
	}
	if errs := rbacValidation.ValidateClusterRoleBindingUpdate(clusterRoleBinding1, clusterRoleBinding2); len(errs) > 0 {
		return
	}
	return
}

func fuzzCompactRules(data []byte) {
	f := fuzz.NewConsumer(data)
	rules := make([]rbacv1.PolicyRule, 0)
	err := f.CreateSlice(&rules)
	if err != nil {
		return
	}
	_, err = rbacregistryvalidation.CompactRules(rules)
	if err != nil {
		return
	}
	return
}

func fuzzValidateResourceQuotaSpec(data []byte) {
	f := fuzz.NewConsumer(data)
	resourceQuotaSpec := &core.ResourceQuotaSpec{}
	err := f.GenerateStruct(resourceQuotaSpec)
	if err != nil {
		return
	}
	fld := &field.Path{}
	err = f.GenerateStruct(fld)
	if err != nil {
		return
	}
	if errs := validation.ValidateResourceQuotaSpec(resourceQuotaSpec, fld); len(errs) > 0 {
		return
	}
	return
}

func fuzzValidateResourceQuotaUpdate(data []byte) {
	f := fuzz.NewConsumer(data)
	newResourceQuota := &core.ResourceQuota{}
	err := f.GenerateStruct(newResourceQuota)
	if err != nil {
		return
	}
	oldResourceQuota := &core.ResourceQuota{}
	err = f.GenerateStruct(oldResourceQuota)
	if err != nil {
		return
	}
	if errs := validation.ValidateResourceQuotaUpdate(newResourceQuota, oldResourceQuota); len(errs) > 0 {
		return
	}
	return
}

func fuzzValidateResourceQuotaStatusUpdate(data []byte) {
	f := fuzz.NewConsumer(data)
	newResourceQuota := &core.ResourceQuota{}
	err := f.GenerateStruct(newResourceQuota)
	if err != nil {
		return
	}
	oldResourceQuota := &core.ResourceQuota{}
	err = f.GenerateStruct(oldResourceQuota)
	if err != nil {
		return
	}
	if errs := validation.ValidateResourceQuotaStatusUpdate(newResourceQuota, oldResourceQuota); len(errs) > 0 {
		return
	}
	return
}

func fuzzValidateServiceStatusUpdate(data []byte) {
	f := fuzz.NewConsumer(data)
	service := &core.Service{}
	err := f.GenerateStruct(service)
	if err != nil {
		return
	}
	oldService := &core.Service{}
	err = f.GenerateStruct(oldService)
	if err != nil {
		return
	}
	if errs := validation.ValidateServiceStatusUpdate(service, oldService); len(errs) > 0 {
		return
	}
	return
}
