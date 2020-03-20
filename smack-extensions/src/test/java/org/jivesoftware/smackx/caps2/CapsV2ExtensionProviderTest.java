package org.jivesoftware.smackx.caps2;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.jivesoftware.smack.test.util.SmackTestUtil;
import org.jivesoftware.smackx.caps2.packet.CapsV2Extension;
import org.jivesoftware.smackx.caps2.provider.CapsV2ExtensionProvider;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

public class CapsV2ExtensionProviderTest {

    @ParameterizedTest
    @EnumSource(SmackTestUtil.XmlPullParserKind.class)
    public void parseTest(SmackTestUtil.XmlPullParserKind parserKind) throws Exception {
        // @formatter:off
        final String capsV2ExtensionString =
                "<c xmlns=\"urn:xmpp:caps\">\n" +
                        "  <hash xmlns=\"urn:xmpp:hashes:2\" algo=\"sha-256\">kzBZbkqJ3ADrj7v08reD1qcWUwNGHaidNUgD7nHpiw8=</hash>\n" +
                        "  <hash xmlns=\"urn:xmpp:hashes:2\" algo=\"sha3-256\">79mdYAfU9rEdTOcWDO7UEAt6E56SUzk/g6TnqUeuD9Q=</hash>\n" +
                        "</c>";
        // @formatter:on
        CapsV2Extension capsV2Extension = SmackTestUtil.parse(capsV2ExtensionString, CapsV2ExtensionProvider.class, parserKind);
        assertNotNull(capsV2Extension);
    }
}
