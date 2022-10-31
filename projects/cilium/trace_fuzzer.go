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

package trace

import (
	"os"
)

func FuzzGetLabelsFromYaml(data []byte) int {
	defer os.Remove("traceFile")
	f, err := os.Create("traceFile")
	if err != nil {
		return 0
	}
	defer f.Close()

	_, err = f.Write(data)
	if err != nil {
		return 0
	}

	_, _ = GetLabelsFromYaml("traceFile")
	return 1
}