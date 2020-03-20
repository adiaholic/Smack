/**
 *
 * Copyright Aditya Borikar 2020
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
package org.jivesoftware.smackx.caps2;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jivesoftware.smackx.disco.packet.DiscoverInfo;
import org.jivesoftware.smackx.disco.packet.DiscoverInfoBuilder;
import org.jivesoftware.smackx.xdata.FormField;
import org.jivesoftware.smackx.xdata.packet.DataForm;

import org.junit.jupiter.api.Test;
import org.jxmpp.stringprep.XmppStringprepException;

public class EntityCapsManagerV2Test {

	Provider bouncyCastleProvider = new BouncyCastleProvider();

	@Test
    public void testSimpleGenerationExample() throws IOException, NoSuchAlgorithmException {
        DiscoverInfo di = createSimplePacket();
        List<String> hashExpected = Arrays.asList("sha-256","sha3-256");
        EntityCapsManagerV2.NodeAlgoHash nodeAlgoHash = EntityCapsManagerV2.generateCapabilityHash(di, hashExpected);
        assertEquals(nodeAlgoHash.getHashForAlgo("sha-256"), "kzBZbkqJ3ADrj7v08reD1qcWUwNGHaidNUgD7nHpiw8=");
        assertEquals(nodeAlgoHash.getHashForAlgo("sha3-256"), "79mdYAfU9rEdTOcWDO7UEAt6E56SUzk/g6TnqUeuD9Q=");
    }

	@Test
    public void testComplexGenerationExample() throws IOException, NoSuchAlgorithmException {
        DiscoverInfo di = createComplexPacket();
        List<String> hashExpected = Arrays.asList("sha-256","sha3-256");
        HashFunctions.addProvider(bouncyCastleProvider);
        EntityCapsManagerV2.NodeAlgoHash nodeAlgoHash = EntityCapsManagerV2.generateCapabilityHash(di, hashExpected);
        assertEquals(nodeAlgoHash.getHashForAlgo("sha-256"), "u79ZroNJbdSWhdSp311mddz44oHHPsEBntQ5b1jqBSY=");
        assertEquals(nodeAlgoHash.getHashForAlgo("sha3-256"), "XpUJzLAc93258sMECZ3FJpebkzuyNXDzRNwQog8eycg=");
    }

    private DiscoverInfo createSimplePacket() throws XmppStringprepException {

        DiscoverInfoBuilder di = DiscoverInfo.builder("disco1");
        DiscoverInfo.Identity i = new DiscoverInfo.Identity("client", "BombusMod", "mobile");
        di.addIdentity(i);
        di.addFeature("http://jabber.org/protocol/si");
        di.addFeature("http://jabber.org/protocol/bytestreams");
        di.addFeature("http://jabber.org/protocol/chatstates");
        di.addFeature("http://jabber.org/protocol/disco#info");
        di.addFeature("http://jabber.org/protocol/disco#items");
        di.addFeature("urn:xmpp:ping");
        di.addFeature("jabber:iq:time");
        di.addFeature("jabber:iq:privacy");
        di.addFeature("jabber:iq:version");
        di.addFeature("http://jabber.org/protocol/rosterx");
        di.addFeature("urn:xmpp:time");
        di.addFeature("jabber:x:oob");
        di.addFeature("http://jabber.org/protocol/ibb");
        di.addFeature("http://jabber.org/protocol/si/profile/file-transfer");
        di.addFeature("urn:xmpp:receipts");
        di.addFeature("jabber:iq:roster");
        di.addFeature("jabber:iq:last");
        return di.build();
    }

    private DiscoverInfo createComplexPacket() {

        DiscoverInfoBuilder di = DiscoverInfo.builder("disco1");

        byte[] complexName = EntityCapsManagerV2.hexStringToByteArray("d0a2d0bad0b0d0b1d0b1d0b5d180");
        String name = new String(complexName, Charset.forName("UTF-8"));

        DiscoverInfo.Identity i1 = new DiscoverInfo.Identity("client", "pc", "Tkabber", "en");
        DiscoverInfo.Identity i2 = new DiscoverInfo.Identity("client", "pc", name, "ru");
        di.addIdentity(i1);
        di.addIdentity(i2);

        di.addFeature("games:board");
        di.addFeature("http://jabber.org/protocol/activity");
        di.addFeature("http://jabber.org/protocol/activity+notify");
        di.addFeature("http://jabber.org/protocol/bytestreams");
        di.addFeature("http://jabber.org/protocol/chatstates");
        di.addFeature("http://jabber.org/protocol/commands");
        di.addFeature("http://jabber.org/protocol/disco#info");
        di.addFeature("http://jabber.org/protocol/disco#items");
        di.addFeature("http://jabber.org/protocol/evil");
        di.addFeature("http://jabber.org/protocol/feature-neg");
        di.addFeature("http://jabber.org/protocol/geoloc");
        di.addFeature("http://jabber.org/protocol/geoloc+notify");
        di.addFeature("http://jabber.org/protocol/ibb");
        di.addFeature("http://jabber.org/protocol/iqibb");
        di.addFeature("http://jabber.org/protocol/mood");
        di.addFeature("http://jabber.org/protocol/mood+notify");
        di.addFeature("http://jabber.org/protocol/rosterx");
        di.addFeature("http://jabber.org/protocol/si");
        di.addFeature("http://jabber.org/protocol/si/profile/file-transfer");
        di.addFeature("http://jabber.org/protocol/tune");
        di.addFeature("http://www.facebook.com/xmpp/messages");
        di.addFeature("http://www.xmpp.org/extensions/xep-0084.html#ns-metadata+notify");
        di.addFeature("jabber:iq:avatar");
        di.addFeature("jabber:iq:browse");
        di.addFeature("jabber:iq:dtcp");
        di.addFeature("jabber:iq:filexfer");
        di.addFeature("jabber:iq:ibb");
        di.addFeature("jabber:iq:inband");
        di.addFeature("jabber:iq:jidlink");
        di.addFeature("jabber:iq:last");
        di.addFeature("jabber:iq:oob");
        di.addFeature("jabber:iq:privacy");
        di.addFeature("jabber:iq:roster");
        di.addFeature("jabber:iq:time");
        di.addFeature("jabber:iq:version");
        di.addFeature("jabber:x:data");
        di.addFeature("jabber:x:event");
        di.addFeature("jabber:x:oob");
        di.addFeature("urn:xmpp:avatar:metadata+notify");
        di.addFeature("urn:xmpp:ping");
        di.addFeature("urn:xmpp:receipts");
        di.addFeature("urn:xmpp:time");

        DataForm df = new DataForm(DataForm.Type.result);

        FormField.Builder ff = FormField.builder("FORM_TYPE");
        ff.setType(FormField.Type.hidden);
        ff.addValue("urn:xmpp:dataforms:softwareinfo");
        df.addField(ff.build());

        ff = FormField.builder("software");
        ff.addValue("Tkabber");
        df.addField(ff.build());

        ff = FormField.builder("software_version");
        ff.addValue("0.11.1-svn-20111216-mod (Tcl/Tk 8.6b2)");
        df.addField(ff.build());

        ff = FormField.builder("os");
        ff.addValue("Windows");
        df.addField(ff.build());

        ff = FormField.builder("os_version");
        ff.addValue("XP");
        df.addField(ff.build());

        di.addExtension(df);

        return di.build();
    }
}
