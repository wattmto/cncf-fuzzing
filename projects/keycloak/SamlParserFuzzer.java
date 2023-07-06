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
import java.io.ByteArrayInputStream;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import org.keycloak.saml.common.exceptions.ParsingException;
import org.keycloak.saml.processing.core.parsers.saml.SAMLParser;

/**
  This fuzzer targets the parse method of SAMLParser class.
  It creates a XMLEventReader with random bytes and
  pass it as a source for the SAMLParser to parse it.
  */
public class SamlParserFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Initialize a XMLEventReader with InputStream source pointing
      // to a random byte array retrieved from the FuzzedDataProvider
      ByteArrayInputStream bais = new ByteArrayInputStream(data.consumeRemainingAsBytes());
      XMLEventReader reader = XMLInputFactory.newInstance().createXMLEventReader(bais);

      // Retrieve a SAMLParser instance and call the parse method
      // with the source pointing to the XMLEventReader
      SAMLParser.getInstance().parse(reader);
    } catch (ParsingException | XMLStreamException e) {
      // Known exception
    }
  }
}
