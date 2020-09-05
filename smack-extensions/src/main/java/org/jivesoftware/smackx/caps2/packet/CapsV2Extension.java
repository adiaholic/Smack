/**
 *
 * Copyright 2020 Aditya Borikar.
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
package org.jivesoftware.smackx.caps2.packet;

import org.jivesoftware.smack.packet.ExtensionElement;
import org.jivesoftware.smack.packet.Stanza;
import org.jivesoftware.smack.packet.XmlEnvironment;
import org.jivesoftware.smack.util.XmlStringBuilder;

import java.util.HashSet;
import java.util.Set;

public class CapsV2Extension implements ExtensionElement {

    public static final String OPTIMIZATION = "urn:xmpp:caps:optimize";
    public static final String NAMESPACE = "urn:xmpp:caps";
    public static final String ELEMENT = "c";
    public Set<HashBuilder> HASHES = new HashSet<>();

    private CapsV2Extension(HashBuilder hashBuilder){
        HASHES.add(hashBuilder);
    }

    public void addHash(HashBuilder hashBuilder) {
        HASHES.add(hashBuilder);
    }

    @Override
    public String getNamespace() {
        return NAMESPACE;
    }

    @Override
    public String getElementName() {
        return ELEMENT;
    }

    @Override
    public CharSequence toXML(XmlEnvironment xmlEnvironment) {
        XmlStringBuilder xml = new XmlStringBuilder(this);
        xml.closeEmptyElement();
        for (HashBuilder hashBuilder: HASHES) {
            xml.append(hashBuilder);
        }
        xml.closeElement(ELEMENT);
        return xml;
    }

    public Set<HashBuilder> getHASHES(){
        return HASHES;
    }

    public static CapsV2Extension from(Stanza stanza) {
        return (CapsV2Extension) stanza.getExtensionElement(ELEMENT, NAMESPACE);
    }

    public static final class HashBuilder implements ExtensionElement{
        private final String ELEMENT = "hash";
        private final String xmlns = "urn:xmpp:hashes:2";
        private String algo;
        private String hash;

        public HashBuilder(){
        }

        public void setAlgo(String algo) {
            this.algo = algo;
        }

        public String getAlgo() {
            return algo;
        }

        public void setHash(String hash) {
            this.hash = hash;
        }

        public String getHash() {
            return hash;
        }

        public CapsV2Extension build() {
            return new CapsV2Extension(this);
        }

        @Override
        public String getNamespace() {
            return xmlns;
        }

        @Override
        public String getElementName() {
            return ELEMENT;
        }

        @Override
        public CharSequence toXML(XmlEnvironment xmlEnvironment) {
            XmlStringBuilder xml = new XmlStringBuilder(this);
            xml.attribute("algo",algo);
            xml.rightAngleBracket();
            xml.append(hash);
            xml.closeElement(ELEMENT);
            return xml;
        };
    }
}
