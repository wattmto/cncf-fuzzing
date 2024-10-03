#!/bin/bash -eu
# Copyright 2022 ADA Logics Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

set -o nounset
set -o pipefail
set -o errexit
set -x

cd "$SRC"
git clone --depth=1 https://github.com/AdamKorcz/go-118-fuzz-build --branch=include-all-test-files
cd go-118-fuzz-build
go build .
mv go-118-fuzz-build /root/go/bin/

# Add more sanitizers
#############################################################################
#cd $SRC/instrumentation
#go run main.go --target_dir=$SRC/kubernetes
#cd $SRC
#############################################################################

cd $SRC/kubernetes
mkdir $SRC/kubernetes/test/fuzz/fuzzing
#go mod edit -replace github.com/AdaLogics/go-fuzz-headers=github.com/AdamKorcz/go-fuzz-headers-1@22e92b7968997eabd210694dd4825dd0d19b697c


export KUBE_FUZZERS=$SRC/cncf-fuzzing/projects/kubernetes

# Move fuzzers from cncf-fuzzing and tests in Kubernetes
#############################################################################

mv $SRC/cncf-fuzzing/projects/kubernetes/roundtrip.go \
   $SRC/kubernetes/staging/src/k8s.io/apimachinery/pkg/api/apitesting/roundtrip/

mv $KUBE_FUZZERS/internal_kubelet_server_fuzzer.go \
   $SRC/kubernetes/pkg/kubelet/server/fuzz_test.go
mv $SRC/kubernetes/pkg/kubelet/server/auth_test.go \
   $SRC/kubernetes/pkg/kubelet/server/auth_test_fuzz.go
mv $SRC/kubernetes/pkg/kubelet/server/server_test.go \
   $SRC/kubernetes/pkg/kubelet/server/server_test_fuzz.go

mv $KUBE_FUZZERS/internal_kubelet_kuberuntime_fuzzer.go \
   $SRC/kubernetes/pkg/kubelet/kuberuntime/fuzz_test.go
mv $SRC/kubernetes/pkg/kubelet/kuberuntime/kuberuntime_manager_test.go \
   $SRC/kubernetes/pkg/kubelet/kuberuntime/kuberuntime_manager_test_fuzz.go

mv $KUBE_FUZZERS/internal_kubelet_fuzzer.go \
   $SRC/kubernetes/pkg/kubelet/fuzz_test.go
mv $KUBE_FUZZERS/kubelet_pods_test_fuzzer.go \
   $SRC/kubernetes/pkg/kubelet/
mv $KUBE_FUZZERS/pod_workers_test_fuzzer.go \
   $SRC/kubernetes/pkg/kubelet/
mv $KUBE_FUZZERS/kubelet_test_fuzzer.go \
   $SRC/kubernetes/pkg/kubelet/
mv $KUBE_FUZZERS/kubelet_node_status_test_fuzzer.go \
   $SRC/kubernetes/pkg/kubelet/

mv $KUBE_FUZZERS/mount-utils_fuzzer.go \
   $SRC/kubernetes/staging/src/k8s.io/mount-utils/fuzz_test.go

mv $KUBE_FUZZERS/deployment_util_fuzzer.go \
   $SRC/kubernetes/pkg/controller/deployment/util/fuzz_test.go

mv $KUBE_FUZZERS/aes_fuzzers_test.go \
   $SRC/kubernetes/test/fuzz/fuzzing/
mv $KUBE_FUZZERS/apiextensions_fuzzers_test.go \
   $SRC/kubernetes/test/fuzz/fuzzing/
mv $KUBE_FUZZERS/api_roundtrip_fuzzers_test.go \
   $SRC/kubernetes/test/fuzz/fuzzing/
mv $KUBE_FUZZERS/apiserver_fuzzers_test.go \
   $SRC/kubernetes/test/fuzz/fuzzing/
mv $KUBE_FUZZERS/converter_fuzzers_test.go \
   $SRC/kubernetes/test/fuzz/fuzzing/
mv $KUBE_FUZZERS/deepcopy_fuzzers_test.go \
   $SRC/kubernetes/test/fuzz/fuzzing/
mv $KUBE_FUZZERS/kubelet_fuzzers_test.go \
   $SRC/kubernetes/test/fuzz/fuzzing/
mv $KUBE_FUZZERS/parser_fuzzers_test.go \
   $SRC/kubernetes/test/fuzz/fuzzing/
mv $KUBE_FUZZERS/roundtrip_fuzzers_test.go \
   $SRC/kubernetes/test/fuzz/fuzzing/
mv $KUBE_FUZZERS/validation_fuzzers_test.go \
   $SRC/kubernetes/test/fuzz/fuzzing/

mkdir -p $SRC/kubernetes/test/fuzz/fuzzing/native_fuzzing && cd $SRC/kubernetes/test/fuzz/fuzzing/native_fuzzing
# Create empty file that imports "github.com/AdamKorcz/go-118-fuzz-build/utils"
# This is a small hack to install this dependency, since it is not used anywhere,
# and Go would therefore remove it from go.mod once we run "go mod tidy && go mod vendor".
go install github.com/AdamKorcz/go-118-fuzz-build@latest
printf "package main\nimport ( \n _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n )\n" > register.go

go mod tidy
go work vendor

# Delete broken fuzzer in 3rd-party dependency.
#find $SRC/kubernetes/vendor/github.com/cilium/ebpf/internal/btf -name "fuzz.go" -exec rm -rf {} \;

# Build the fuzzers
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzParseQuantity fuzz_parse_quantity
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzMeta1ParseToLabelSelector fuzz_meta1_parse_to_label_selector
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzParseSelector fuzz_parse_selector
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzLabelsParse fuzz_labels_parse
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzParseGroupVersion fuzz_parse_group_version
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzParseResourceArg fuzz_parse_resource_arg
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzParseVersion fuzz_parse_version
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzParsePrivateKeyPEM fuzz_parse_private_pem
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzParsePublicKeysPEM fuzz_parse_public_keys_pem
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzParseHostPort fuzz_parse_host_port
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzUrlsMatch fuzz_urls_match
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzParseCSR fuzz_parse_csr
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzParseEnv fuzz_parse_env
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzParseQOSReserve fuzz_parse_qos_reserve
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzParseCPUSet fuzz_parse_cpu_set
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzParseImageName fuzz_parse_image_name
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzApiRoundtrip fuzz_api_roundtrip
compile_native_go_fuzzer k8s.io/kubernetes/pkg/kubelet/kuberuntime FuzzKubeRuntime fuzz_kube_runtime
compile_native_go_fuzzer k8s.io/kubernetes/pkg/kubelet FuzzSyncPod fuzz_sync_pod
compile_native_go_fuzzer k8s.io/kubernetes/pkg/kubelet FuzzStrategicMergePatch fuzz_strategic_merge_patch
compile_native_go_fuzzer k8s.io/kubernetes/pkg/kubelet FuzzconvertToAPIContainerStatuses fuzz_convert_to_api_container_statuses
compile_native_go_fuzzer k8s.io/kubernetes/pkg/kubelet FuzzHandlePodCleanups fuzz_handle_pod_cleanups
compile_native_go_fuzzer k8s.io/kubernetes/pkg/kubelet FuzzMakeEnvironmentVariables fuzz_make_environment_variables
compile_native_go_fuzzer k8s.io/kubernetes/pkg/controller/deployment/util FuzzEntireDeploymentUtil fuzz_entire_deployment_util
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzDeepCopy fuzz_deep_copy
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzAesRoundtrip fuzz_aes_roundtrip
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzLoadPolicyFromBytes fuzz_load_policy_from_bytes
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing RegistryFuzzer registry_fuzzer
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzUnrecognized fuzz_unrecognized
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzRoundTripSpecificKind fuzz_roundtrip_specific_kind
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzControllerRoundtrip fuzz_controller_roundtrip
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzKubeletSchemeRoundtrip fuzz_kubelet_scheme_roundtrip
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzProxySchemeRoundtrip fuzz_proxy_scheme_roundtrip
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzRoundTripType fuzz_rountrip_type
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzReadLogs fuzz_read_logs
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzRoundtrip fuzz_roundtrip
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzAllValidation fuzz_all_validation
# disable this fuzzer for now
#compile_native_go_fuzzer k8s.io/kubernetes/pkg/kubelet/server FuzzRequest fuzz_request

# Done building Go 1.18 fuzzers
#############################################################################

# Delete broken fuzzer from a 3rd-party dependency
#find $SRC/kubernetes/vendor/github.com/cilium/ebpf/internal/btf -name "fuzz.go" -exec rm -rf {} \;

# Create fuzzers for all marshaling and unmarshaling routines
#############################################################################

cd $SRC/kubernetes
if [ "$SANITIZER" != "coverage" ]; then
   grep -r ") Marshal()" . > $SRC/grep_result.txt
   mv $SRC/cncf-fuzzing/projects/kubernetes/autogenerate.py ./
   python3 autogenerate.py --input_file $SRC/grep_result.txt
   mv api_marshaling_fuzzer.go $SRC/kubernetes/test/fuzz/fuzzing/
fi
# Done creating fuzzer for all marshaling and unmarshaling routines
#############################################################################

if [ "$SANITIZER" != "coverage" ]; then
   compile_native_go_fuzzer kubernetes/test/fuzz/fuzzing FuzzApiMarshaling fuzz_api_marshaling
fi
