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
	"io"
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/version"
	"k8s.io/client-go/util/keyutil"
	envutil "k8s.io/kubectl/pkg/cmd/set/env"
	"k8s.io/kubectl/pkg/util/certificate"
	kubeadmutil "k8s.io/kubernetes/cmd/kubeadm/app/util"
	"k8s.io/kubernetes/pkg/credentialprovider"
	"k8s.io/kubernetes/pkg/kubelet/cm"
	"k8s.io/kubernetes/pkg/util/parsers"
	"k8s.io/utils/cpuset"
)

// FuzzParseQuantity implements a fuzzer
// that targets resource.ParseQuantity
func FuzzParseQuantity(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = resource.ParseQuantity(string(data))
		return
	})
}

// FuzzMeta1ParseToLabelSelector implements a fuzzer
// that targets metav1.ParseToLabelSelector
func FuzzMeta1ParseToLabelSelector(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = metav1.ParseToLabelSelector(string(data))
		return
	})
}

// FuzzParseSelector implements a fuzzer
// that targets fields.ParseSelector
func FuzzParseSelector(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = fields.ParseSelector(string(data))
		return
	})
}

// FuzzLabelsParse implements a fuzzer
// that targets labels.Parse
func FuzzLabelsParse(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = labels.Parse(string(data))
		return
	})
}

// FuzzParseGroupVersion implements a fuzzer
// that targets schema.ParseGroupVersion
func FuzzParseGroupVersion(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = schema.ParseGroupVersion(string(data))
		return
	})
}

// FuzzParseResourceArg implements a fuzzer
// that targets schema.ParseResourceArg
func FuzzParseResourceArg(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = schema.ParseResourceArg(string(data))
		return
	})
}

// FuzzParseVersion implements a fuzzer
// that targets:
// - version.ParseSemantic,
// - version/(*Version).String()
// - version.ParseGeneric
// - version/(*Version).AtLeast(*Version)
func FuzzParseVersion(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fdp := fuzz.NewConsumer(data)
		vString1, err := fdp.GetString()
		if err != nil {
			return
		}
		v1, err := version.ParseSemantic(vString1)
		if err != nil {
			return
		}

		// Test if the Version will crash (*Version).String()
		_ = v1.String()

		vString2, err := fdp.GetString()
		if err != nil {
			return
		}
		v2, err := version.ParseGeneric(vString2)
		if err != nil {
			return
		}
		_ = v1.AtLeast(v2)
		return
	})
}

// FuzzParsePrivateKeyPEM implements a fuzzer
// that targets keyutil.ParsePrivateKeyPEM
func FuzzParsePrivateKeyPEM(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = keyutil.ParsePrivateKeyPEM(data)
		return
	})
}

// FuzzParsePublicKeysPEM implements a fuzzer
// that targets keyutil.ParsePublicKeysPEM
func FuzzParsePublicKeysPEM(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = keyutil.ParsePublicKeysPEM(data)
		return
	})
}

// FuzzParseHostPort implements a fuzzer
// that targets kubeadmutil.ParseHostPort
func FuzzParseHostPort(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = kubeadmutil.ParseHostPort(string(data))
		return
	})
}

// FuzzUrlsMatch implements a fuzzer
// that targets credentialprovider.URLsMatchStr
func FuzzUrlsMatch(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fdp := fuzz.NewConsumer(data)
		glob, err := fdp.GetString()
		if err != nil {
			return
		}
		target, err := fdp.GetString()
		if err != nil {
			return
		}
		_, _ = credentialprovider.URLsMatchStr(glob, target)
		return
	})
}

// FuzzParseCSR implements a fuzzer
// that targets certificate.ParseCSR
func FuzzParseCSR(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = certificate.ParseCSR(data)
		return
	})
}

// FuzzParseEnv implements a fuzzer
// that targets envutil.ParseEnv
func FuzzParseEnv(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fdp := fuzz.NewConsumer(data)

		// Create a pseudo-random spec.
		// Will be used as argument to the fuzz target

		// length of slice:
		qty, err := fdp.GetInt()
		if err != nil {
			return
		}
		spec := make([]string, qty, qty)

		// fill slice with values
		for i := 0; i < qty; i++ {
			s, err := fdp.GetString()
			if err != nil {
				return
			}
			spec = append(spec, s)
		}
		var r io.Reader
		_, _, _, _ = envutil.ParseEnv(spec, r)
		return
	})
}

// FuzzParseQOSReserve implements a fuzzer
// that targets cm.ParseQOSReserved
func FuzzParseQOSReserve(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fdp := fuzz.NewConsumer(data)

		// Create a pseudo-random map.
		// Will be used as argument to the fuzz target
		m := make(map[string]string)
		err := fdp.FuzzMap(&m)
		if err != nil {
			return
		}
		_, _ = cm.ParseQOSReserved(m)
		return
	})
}

// FuzzParseCPUSet implements a fuzzer
// that targets:
// - cpuset.Parse
// - cpuset/(CPUSet).String
func FuzzParseCPUSet(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		cs, err := cpuset.Parse(string(data))
		if err != nil {
			return
		}
		_ = cs.String()
		return
	})
}

// FuzzParseImageName implements a fuzzer
// that targets parsers.ParseImageName
func FuzzParseImageName(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _, _ = parsers.ParseImageName(string(data))
		return
	})
}
