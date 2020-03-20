/**
 *
 * Copyright 2020 Aditya Borikar
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jivesoftware.smackx.caps2.provider;

import org.jivesoftware.smack.packet.XmlEnvironment;
import org.jivesoftware.smack.parsing.SmackParsingException;
import org.jivesoftware.smack.provider.ExtensionElementProvider;
import org.jivesoftware.smack.xml.XmlPullParser;
import org.jivesoftware.smack.xml.XmlPullParserException;
import org.jivesoftware.smackx.caps2.packet.CapsV2Extension;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

public class CapsV2ExtensionProvider extends ExtensionElementProvider<CapsV2Extension> {
    @Override
    public CapsV2Extension parse(XmlPullParser parser, int initialDepth, XmlEnvironment xmlEnvironment) throws XmlPullParserException, IOException, SmackParsingException {

        Set<CapsV2Extension.HashElement> hashBuilderSet = new HashSet<>();

        CapsV2Extension capsV2Extension = new CapsV2Extension(null);

        String name = parser.getName();
        String namespace = parser.getNamespace();
        if (!name.equals(CapsV2Extension.ELEMENT) || !namespace.equals(CapsV2Extension.NAMESPACE)) {
            return null;
        }
        XmlPullParser.TagEvent tag = parser.nextTag();
        loop : while (true) {
            switch (tag) {
                case START_ELEMENT:
                    if (!parser.getName().equals("hash")){
                        return null;
                    }
                    String algo = parser.getAttributeValue(0);
                    String hash = parser.nextText();
                    CapsV2Extension.HashElement hashElement = capsV2Extension.getNewHashElement();
                    hashElement.setAlgo(algo);
                    hashElement.setHash(hash);
                    hashBuilderSet.add(hashElement);
                    break;
                case END_ELEMENT:
                    if (!parser.getName().equals(CapsV2Extension.ELEMENT)){
                        return null;
                    }
                    break loop;
                default:
            }
            tag = parser.nextTag();
        }

        return new CapsV2Extension(hashBuilderSet);
    }
}
