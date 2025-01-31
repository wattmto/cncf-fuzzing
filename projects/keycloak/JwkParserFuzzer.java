// Copyright 2023 the cncf-fuzzing authors
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
///////////////////////////////////////////////////////////////////////////
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.keycloak.jose.jwk.JWKParser;

/**
 * This fuzzer targets the methods in JWKParser. It passes random string to the JWKParser object and
 * call other methods that rely on the parsing result randomly.
 */
public class JwkParserFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Create a new JWKParser instance
      JWKParser parser = JWKParser.create();

      // Call the parse method with random string
      parser.parse(data.consumeString(data.consumeInt(0, 10000)));

      // Randomly executing methods in JWKParser
      // which rely on the parsing result
      if (data.consumeBoolean()) {
        parser.toPublicKey();
      } else {
        parser.isKeyTypeSupported(data.consumeString(data.consumeInt(0, 10000)));
      }
    } catch (RuntimeException e) {
      // Known exception
    }
  }
}
