// Copyright 2022 ADA Logics Ltd
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

package util

import (
	"context"
	apps "k8s.io/api/apps/v1"
	intstrutil "k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/klog/v2"
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"

	"time"
)

var (
	functionsToCall = map[int]string {
		0: "fuzzSetDeploymentCondition",
		1: "fuzzRemoveDeploymentCondition",
		2: "fuzzSetDeploymentRevision",
		3: "fuzzMaxAndLastRevision",
		4: "fuzzSetNewReplicaSetAnnotations",
		5: "fuzzSetDeploymentAnnotationsTo",
		6: "fuzzFindActiveOrLatest",
		7: "fuzzGetDesiredReplicasAnnotation",
		8: "fuzzSetReplicasAnnotations",
		9: "fuzzReplicasAnnotationsNeedUpdate",
		10: "fuzzMaxUnavailable",
		11: "fuzzMinAvailable",
		12: "fuzzMaxSurge",
		13: "fuzzGetProportion",
		14: "fuzzFindNewReplicaSet",
		15: "fuzzFindOldReplicaSets",
		16: "fuzzGetReplicaCountForReplicaSets",
		17: "fuzzGetActualReplicaCountForReplicaSets",
		18: "fuzzGetReadyReplicaCountForReplicaSets",
		19: "fuzzGetAvailableReplicaCountForReplicaSets",
		20: "fuzzNewRSNewReplicas",
		21: "fuzzIsSaturated",
		22: "fuzzResolveFenceposts",
		23: "fuzzGetDeploymentsForReplicaSet",
	}
)

func FuzzEntireDeploymentUtil(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 10 {
			return
		}
		functionToCall := int(data[0])
		switch functionsToCall[functionToCall%len(functionsToCall)] {
		case "fuzzSetDeploymentCondition":
			fuzzSetDeploymentCondition(data[1:])
		case "fuzzRemoveDeploymentCondition":
			fuzzRemoveDeploymentCondition(data[1:])
		case "fuzzSetDeploymentRevision":
			fuzzSetDeploymentRevision(data[1:])
		case "fuzzMaxAndLastRevision":
			fuzzMaxAndLastRevision(data[1:])
		case "fuzzSetNewReplicaSetAnnotations":
			fuzzSetNewReplicaSetAnnotations(data[1:])
		case "fuzzSetDeploymentAnnotationsTo":
			fuzzSetDeploymentAnnotationsTo(data[1:])
		case "fuzzFindActiveOrLatest":
			fuzzFindActiveOrLatest(data[1:])
		case "fuzzGetDesiredReplicasAnnotation":
			fuzzGetDesiredReplicasAnnotation(data[1:])
		case "fuzzSetReplicasAnnotations":
			fuzzSetReplicasAnnotations(data[1:])
		case "fuzzReplicasAnnotationsNeedUpdate":
			fuzzReplicasAnnotationsNeedUpdate(data[1:])
		case "fuzzMaxUnavailable":
			fuzzMaxUnavailable(data[1:])
		case "fuzzMinAvailable":
			fuzzMinAvailable(data[1:])
		case "fuzzMaxSurge":
			fuzzMaxSurge(data[1:])
		case "fuzzGetProportion":
			fuzzGetProportion(data[1:])
		case "fuzzFindNewReplicaSet":
			fuzzFindNewReplicaSet(data[1:])
		case "fuzzFindOldReplicaSets":
			fuzzFindOldReplicaSets(data[1:])
		case "fuzzGetReplicaCountForReplicaSets"
			fuzzGetReplicaCountForReplicaSets(data[1:])
		case "fuzzGetActualReplicaCountForReplicaSets":
			fuzzGetActualReplicaCountForReplicaSets(data[1:])
		case "fuzzGetReadyReplicaCountForReplicaSets":
			fuzzGetReadyReplicaCountForReplicaSets(data[1:])
		case "fuzzGetAvailableReplicaCountForReplicaSets":
			fuzzGetAvailableReplicaCountForReplicaSets(data[1:])
		case "fuzzNewRSNewReplicas":
			fuzzNewRSNewReplicas(data[1:])
		case "fuzzIsSaturated":
			fuzzIsSaturated(data[1:])
		case "fuzzResolveFenceposts":
			fuzzResolveFenceposts(data[1:])
		case "fuzzGetDeploymentsForReplicaSet":
			fuzzGetDeploymentsForReplicaSet(data[1:])
		}
		return
	})
}

func fuzzSetDeploymentCondition(data []byte) {
	// Not supported
	return
}

func fuzzRemoveDeploymentCondition(data []byte) {
	// Not supported
	return
}

func fuzzSetDeploymentRevision(data []byte) {
	f := fuzz.NewConsumer(data)
	deployment := &apps.Deployment{}
	err := f.GenerateStruct(deployment)
	if err != nil {
		return
	}
	revision, err := f.GetString()
	if err != nil {
		return
	}
	SetDeploymentRevision(deployment, revision)
	return
}

func fuzzMaxAndLastRevision(data []byte) {
	f := fuzz.NewConsumer(data)
	allRSs := make([]*apps.ReplicaSet, 0)
	err := f.CreateSlice(&allRSs)
	if err != nil {
		return
	}
	max, err := f.GetBool()
	if err != nil {
		return
	}
	logger := klog.Background()
	if max {
		_ = MaxRevision(logger, allRSs)
	} else {
		LastRevision(logger, allRSs)
	}
	return
}

func fuzzSetNewReplicaSetAnnotations(data []byte) {
	f := fuzz.NewConsumer(data)
	deployment := &apps.Deployment{}
	err := f.GenerateStruct(deployment)
	if err != nil {
		return
	}
	newRS := &apps.ReplicaSet{}
	err = f.GenerateStruct(newRS)
	if err != nil {
		return
	}
	newRevision, err := f.GetString()
	if err != nil {
		return
	}
	exists, err := f.GetBool()
	if err != nil {
		return
	}

	revHistoryLimitInChars, err := f.GetInt()
	if err != nil {
		return
	}
	SetNewReplicaSetAnnotations(context.Background(), deployment, newRS, newRevision, exists, revHistoryLimitInChars)
	return
}

func fuzzSetDeploymentAnnotationsTo(data []byte) {
	f := fuzz.NewConsumer(data)
	deployment := &apps.Deployment{}
	err := f.GenerateStruct(deployment)
	if err != nil {
		return
	}
	rollbackToRS := &apps.ReplicaSet{}
	err = f.GenerateStruct(rollbackToRS)
	if err != nil {
		return
	}
	SetDeploymentAnnotationsTo(deployment, rollbackToRS)
	return
}

func fuzzFindActiveOrLatest(data []byte) {
	f := fuzz.NewConsumer(data)
	newRS := &apps.ReplicaSet{}
	err := f.GenerateStruct(newRS)
	if err != nil {
		return
	}
	oldRSs := make([]*apps.ReplicaSet, 0)
	err = f.CreateSlice(&oldRSs)
	if err != nil {
		return
	}
	_ = FindActiveOrLatest(newRS, oldRSs)
	return
}

func fuzzGetDesiredReplicasAnnotation(data []byte) {
	f := fuzz.NewConsumer(data)
	rs := &apps.ReplicaSet{}
	err := f.GenerateStruct(rs)
	if err != nil {
		return
	}
	_, _ = GetDesiredReplicasAnnotation(klog.FromContext(context.Background()), rs)
	return
}

func fuzzSetReplicasAnnotations(data []byte) {
	f := fuzz.NewConsumer(data)
	rs := &apps.ReplicaSet{}
	err := f.GenerateStruct(rs)
	if err != nil {
		return
	}
	desiredReplicas, err := f.GetInt()
	if err != nil {
		return
	}
	maxReplicas, err := f.GetInt()
	if err != nil {
		return
	}
	SetReplicasAnnotations(rs, int32(desiredReplicas), int32(maxReplicas))
	return
}

func fuzzReplicasAnnotationsNeedUpdate(data []byte) {
	f := fuzz.NewConsumer(data)
	rs := &apps.ReplicaSet{}
	err := f.GenerateStruct(rs)
	if err != nil {
		return
	}
	desiredReplicas, err := f.GetInt()
	if err != nil {
		return
	}
	maxReplicas, err := f.GetInt()
	if err != nil {
		return
	}
	ReplicasAnnotationsNeedUpdate(rs, int32(desiredReplicas), int32(maxReplicas))
	return
}

func fuzzMaxUnavailable(data []byte) {
	f := fuzz.NewConsumer(data)
	deployment := apps.Deployment{}
	err := f.GenerateStruct(&deployment)
	if err != nil {
		return
	}
	_ = MaxUnavailable(deployment)
	return
}

func fuzzMinAvailable(data []byte) {
	f := fuzz.NewConsumer(data)
	deployment := &apps.Deployment{}
	err := f.GenerateStruct(deployment)
	if err != nil {
		return
	}
	_ = MinAvailable(deployment)
	return
}

func fuzzMaxSurge(data []byte) {
	f := fuzz.NewConsumer(data)
	deployment := apps.Deployment{}
	err := f.GenerateStruct(&deployment)
	if err != nil {
		return
	}
	_ = MaxSurge(deployment)
	return
}

func fuzzGetProportion(data []byte) {
	f := fuzz.NewConsumer(data)
	rs := &apps.ReplicaSet{}
	err := f.GenerateStruct(rs)
	if err != nil {
		return
	}
	deployment := apps.Deployment{}
	err = f.GenerateStruct(&deployment)
	if err != nil {
		return
	}
	deploymentReplicasToAdd, err := f.GetInt()
	if err != nil {
		return
	}
	deploymentReplicasAdded, err := f.GetInt()
	if err != nil {
		return
	}
	_ = GetProportion(klog.FromContext(context.Background()), rs, deployment, int32(deploymentReplicasToAdd), int32(deploymentReplicasAdded))
	return
}

func fuzzFindNewReplicaSet(data []byte) {
	f := fuzz.NewConsumer(data)
	deployment := &apps.Deployment{}
	err := f.GenerateStruct(deployment)
	if err != nil {
		return
	}
	rsList := make([]*apps.ReplicaSet, 0)
	err = f.CreateSlice(&rsList)
	if err != nil {
		return
	}
	_ = FindNewReplicaSet(deployment, rsList)
	return
}

func fuzzFindOldReplicaSets(data []byte) {
	f := fuzz.NewConsumer(data)
	deployment := &apps.Deployment{}
	err := f.GenerateStruct(deployment)
	if err != nil {
		return
	}
	rsList := make([]*apps.ReplicaSet, 0)
	err = f.CreateSlice(&rsList)
	if err != nil {
		return
	}
	_, _ = FindOldReplicaSets(deployment, rsList)
	return
}

func fuzzGetReplicaCountForReplicaSets(data []byte) {
	f := fuzz.NewConsumer(data)
	replicaSets := make([]*apps.ReplicaSet, 0)
	err := f.CreateSlice(&replicaSets)
	if err != nil {
		return
	}
	_ = GetReplicaCountForReplicaSets(replicaSets)
	return
}

func fuzzGetActualReplicaCountForReplicaSets(data []byte) {
	f := fuzz.NewConsumer(data)
	replicaSets := make([]*apps.ReplicaSet, 0)
	err := f.CreateSlice(&replicaSets)
	if err != nil {
		return
	}
	_ = GetActualReplicaCountForReplicaSets(replicaSets)
	return
}

func fuzzGetReadyReplicaCountForReplicaSets(data []byte) {
	f := fuzz.NewConsumer(data)
	replicaSets := make([]*apps.ReplicaSet, 0)
	err := f.CreateSlice(&replicaSets)
	if err != nil {
		return
	}
	_ = GetReadyReplicaCountForReplicaSets(replicaSets)
	return
}

func fuzzGetAvailableReplicaCountForReplicaSets(data []byte) {
	f := fuzz.NewConsumer(data)
	replicaSets := make([]*apps.ReplicaSet, 0)
	err := f.CreateSlice(&replicaSets)
	if err != nil {
		return
	}
	_ = GetAvailableReplicaCountForReplicaSets(replicaSets)
	return
}

func fuzzNewRSNewReplicas(data []byte) {
	f := fuzz.NewConsumer(data)
	deployment := &apps.Deployment{}
	err := f.GenerateStruct(deployment)
	if err != nil {
		return
	}
	allRSs := make([]*apps.ReplicaSet, 0)
	err = f.CreateSlice(&allRSs)
	if err != nil {
		return
	}
	newRS := &apps.ReplicaSet{}
	err = f.GenerateStruct(newRS)
	if err != nil {
		return
	}
	_, _ = NewRSNewReplicas(deployment, allRSs, newRS)
	return
}

func fuzzIsSaturated(data []byte) {
	f := fuzz.NewConsumer(data)
	deployment := &apps.Deployment{}
	err := f.GenerateStruct(deployment)
	if err != nil {
		return
	}
	rs := &apps.ReplicaSet{}
	err = f.GenerateStruct(rs)
	if err != nil {
		return
	}
	_ = IsSaturated(deployment, rs)
	return
}

func fuzzResolveFenceposts(data []byte) {
	f := fuzz.NewConsumer(data)
	maxSurge := &intstrutil.IntOrString{}
	err := f.GenerateStruct(maxSurge)
	if err != nil {
		return
	}
	maxUnavailable := &intstrutil.IntOrString{}
	err = f.GenerateStruct(maxUnavailable)
	if err != nil {
		return
	}
	desired, err := f.GetInt()
	if err != nil {
		return
	}
	_, _, _ = ResolveFenceposts(maxSurge, maxUnavailable, int32(desired))
	return
}

func fuzzGetDeploymentsForReplicaSet(data []byte) {
	fakeInformerFactory := informers.NewSharedInformerFactory(&fake.Clientset{}, 0*time.Second)

	f := fuzz.NewConsumer(data)
	rs := &apps.ReplicaSet{}
	err := f.GenerateStruct(rs)
	if err != nil {
		return
	}
	GetDeploymentsForReplicaSet(fakeInformerFactory.Apps().V1().Deployments().Lister(), rs)
	return
}
