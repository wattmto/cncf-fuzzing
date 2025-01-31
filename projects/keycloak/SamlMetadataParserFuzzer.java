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
import java.nio.charset.StandardCharsets;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import org.keycloak.saml.common.exceptions.ParsingException;
import org.keycloak.saml.common.parsers.StaxParser;
import org.keycloak.saml.processing.core.parsers.saml.mdattr.SAMLEntityAttributesParser;
import org.keycloak.saml.processing.core.parsers.saml.mdui.SAMLUIInfoParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLArtifactResolutionServiceParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLAssertinIDRequestServiceParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLAssertionConsumerServiceParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLAttributeAuthorityDescriptorParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLAttributeConsumingServiceParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLAttributeParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLAttributeServiceParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLAuthnAuthorityDescriptorParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLAuthnQueryServiceParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLAuthzServiceParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLContactPersonParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLEncryptionMethodParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLEntityDescriptorParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLExtensionsParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLIDPSSODescriptorParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLKeyDescriptorParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLManageNameIDServiceParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLNameIDMappingServiceParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLOrganizationParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLPDPDescriptorParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLRequestedAttributeParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLSPSSODescriptorParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLSingleLogoutServiceParser;
import org.keycloak.saml.processing.core.parsers.saml.metadata.SAMLSingleSignOnServiceParser;

/**
 * This fuzzer targets the parse method of all instances and implementation of StaxParser in
 * org.keycloak.saml.processing.core.parsers.saml.metadata package. It creates a XMLEventReader with
 * random bytes in UTF-8 encoding and pass it as a source for the a random SAML parser to parse it.
 */
public class SamlMetadataParserFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Initialise a StaxParser object
      StaxParser parser = null;

      // Retrieve or create a random SAML Parser object
      // instance and run the parse method with the
      // random data provided by the XMLEventReader
      // object created above
      switch (data.consumeInt(1, 26)) {
        case 1:
          parser = SAMLEntityAttributesParser.getInstance();
        case 2:
          parser = SAMLUIInfoParser.getInstance();
        case 3:
          parser = SAMLArtifactResolutionServiceParser.getInstance();
        case 4:
          parser = SAMLAssertinIDRequestServiceParser.getInstance();
        case 5:
          parser = SAMLAssertionConsumerServiceParser.getInstance();
        case 6:
          parser = SAMLAttributeAuthorityDescriptorParser.getInstance();
        case 7:
          parser = SAMLAttributeConsumingServiceParser.getInstance();
        case 8:
          parser = SAMLAttributeParser.getInstance();
        case 9:
          parser = SAMLAttributeServiceParser.getInstance();
        case 10:
          parser = SAMLAuthnAuthorityDescriptorParser.getInstance();
        case 11:
          parser = SAMLAuthnQueryServiceParser.getInstance();
        case 12:
          parser = SAMLAuthzServiceParser.getInstance();
        case 13:
          parser = SAMLContactPersonParser.getInstance();
        case 14:
          parser = SAMLEncryptionMethodParser.getInstance();
        case 15:
          parser = SAMLEntityDescriptorParser.getInstance();
        case 16:
          parser = SAMLExtensionsParser.getInstance();
        case 17:
          parser = SAMLIDPSSODescriptorParser.getInstance();
        case 18:
          parser = SAMLKeyDescriptorParser.getInstance();
        case 19:
          parser = SAMLManageNameIDServiceParser.getInstance();
        case 20:
          parser = SAMLNameIDMappingServiceParser.getInstance();
        case 21:
          parser = SAMLOrganizationParser.getInstance();
        case 22:
          parser = SAMLPDPDescriptorParser.getInstance();
        case 23:
          parser = SAMLRequestedAttributeParser.getInstance();
        case 24:
          parser = SAMLSingleLogoutServiceParser.getInstance();
        case 25:
          parser = SAMLSingleSignOnServiceParser.getInstance();
        case 26:
          parser = SAMLSPSSODescriptorParser.getInstance();
      }

      // Initialize a XMLEventReader with InputStream source pointing
      // to a random byte array in UTF-8 encoding retrieved from the
      // FuzzedDataProvider
      byte[] input = data.consumeRemainingAsString().getBytes(StandardCharsets.UTF_8);
      ByteArrayInputStream bais = new ByteArrayInputStream(input);
      XMLEventReader reader = XMLInputFactory.newInstance().createXMLEventReader(bais);

      parser.parse(reader);
    } catch (ParsingException | XMLStreamException | RuntimeException e) {
      // Known exception
    }
  }
}
