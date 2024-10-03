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
	stdlibAes "crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"

	"k8s.io/apiserver/pkg/storage/value"
	aestransformer "k8s.io/apiserver/pkg/storage/value/encrypt/aes"
)

func FuzzAesRoundtrip(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		f := fuzz.NewConsumer(data)
		cipherBytes, err := f.GetBytes()
		if err != nil {
			return
		}
		if len(cipherBytes) == 0 {
			return
		}

		randBytes, err := f.GetBytes()
		if err != nil {
			return
		}
		if len(randBytes) == 0 {
			return
		}

		aesBlock, err := stdlibAes.NewCipher(cipherBytes)
		if err != nil {
			return
		}

		callGCMT, err := f.GetBool()
		if err != nil {
			return
		}
		if callGCMT {
			err = testGCMTTransformer(randBytes, aesBlock)
			if err != nil {
				panic(err)
			}
		} else {
			err = testCBCTransformer(randBytes, aesBlock)
		}

		return
	})
}

func testGCMTTransformer(randBytes []byte, aesBlock cipher.Block) error {
	transformer, err := aestransformer.NewGCMTransformer(aesBlock)
	if err != nil {
		return err
	}
	defaultContext := value.DefaultContext("")
	ciphertext, err := transformer.TransformToStorage(context.Background(), randBytes, defaultContext)
	if err != nil {
		return fmt.Errorf("TransformToStorage error = %v\n", err)
	}
	result, stale, err := transformer.TransformFromStorage(context.Background(), ciphertext, defaultContext)
	if err != nil {
		return fmt.Errorf("TransformFromStorage error = %v\n", err)
	}
	if stale {
		return fmt.Errorf("unexpected stale output\n")
	}
	if !reflect.DeepEqual(randBytes, result) {
		return fmt.Errorf("Round trip failed len=%d\noriginal:\n%s\nresult:\n%s\n", len(randBytes), hex.Dump(randBytes), hex.Dump(result))
	}
	return nil
}

func testCBCTransformer(randBytes []byte, aesBlock cipher.Block) error {
	transformer := aestransformer.NewCBCTransformer(aesBlock)
	defaultContext := value.DefaultContext("")
	ciphertext, err := transformer.TransformToStorage(context.Background(), randBytes, defaultContext)
	if err != nil {
		return fmt.Errorf("TransformToStorage error = %v\n", err)
	}
	result, stale, err := transformer.TransformFromStorage(context.Background(), ciphertext, defaultContext)
	if err != nil {
		return fmt.Errorf("TransformFromStorage error = %v\n", err)
	}
	if stale {
		return fmt.Errorf("unexpected stale output\n")
	}
	if !reflect.DeepEqual(randBytes, result) {
		return fmt.Errorf("Round trip failed len=%d\noriginal:\n%s\nresult:\n%s\n", len(randBytes), hex.Dump(randBytes), hex.Dump(result))
	}
	return nil
}
