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
package org.jivesoftware.smackx.caps2;

import org.igniterealtime.smack.inttest.AbstractSmackIntegrationTest;
import org.igniterealtime.smack.inttest.SmackIntegrationTest;
import org.igniterealtime.smack.inttest.SmackIntegrationTestEnvironment;
import org.jivesoftware.smack.SmackException;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.filter.AndFilter;
import org.jivesoftware.smack.filter.FromMatchesFilter;
import org.jivesoftware.smack.filter.PresenceTypeFilter;
import org.jivesoftware.smack.roster.RosterUtil;
import org.jivesoftware.smackx.caps.EntityCapsManager;
import org.jivesoftware.smackx.disco.ServiceDiscoveryManager;
import org.jivesoftware.smackx.disco.packet.DiscoverInfo;
import org.junit.AfterClass;
import org.junit.BeforeClass;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.*;

public class EntityCaps2Test extends AbstractSmackIntegrationTest {

    private final EntityCapsManagerV2 ecmTwo;
    private final ServiceDiscoveryManager sdmOne;
    private final ServiceDiscoveryManager sdmTwo;

    public EntityCaps2Test(SmackIntegrationTestEnvironment<?> environment) throws IOException, NoSuchAlgorithmException {
        super(environment);
        List<String> hashExpected = Arrays.asList("sha-256","sha3-256");
        ecmTwo = EntityCapsManagerV2.getInstanceFor(environment.conTwo,hashExpected);
        sdmOne = ServiceDiscoveryManager.getInstanceFor(environment.conOne);
        sdmTwo = ServiceDiscoveryManager.getInstanceFor(environment.conTwo);
    }

    @BeforeClass
    public void setUp() throws SmackException.NotLoggedInException, TimeoutException, SmackException.NotConnectedException, InterruptedException {
        RosterUtil.ensureSubscribed(conOne, conTwo, timeout);
    }

    @AfterClass
    public void tearDown() throws SmackException.NotConnectedException, InterruptedException {
        RosterUtil.ensureNotSubscribedToEachOther(conOne, conTwo);
        ServiceDiscoveryManager[] sdms = new ServiceDiscoveryManager[] { sdmOne, sdmTwo };
        for (ServiceDiscoveryManager sdm : sdms) {
            for (String dummyFeature : dummyFeatures) {
                sdm.removeFeature(dummyFeature);
            }
        }
    }

    @SmackIntegrationTest
    public void testLocalEntityCapsV2() throws XMPPException.XMPPErrorException, SmackException.NotConnectedException, InterruptedException, SmackException.NoResponseException {
        final String dummyFeature = getNewDummyFeature();

        DiscoverInfo info = EntityCapsManagerV2.getDiscoveryInfoBy(ecmTwo.generateCapabilityHashNodes("sha-1"));
        assertFalse(info.containsFeature(dummyFeature));

        dropWholeEntityCapsCache();

        performActionAndWaitUntilStanzaReceived(new Runnable() {
            @Override
            public void run() {
                sdmTwo.addFeature(dummyFeature);
            }
        },conOne, new AndFilter(PresenceTypeFilter.AVAILABLE, FromMatchesFilter.create(conTwo.getUser())));

        info = EntityCapsManagerV2.getDiscoveryInfoBy(ecmTwo.generateCapabilityHashNodes("sha-1"));
        assertNotNull(info);
        assertTrue(info.containsFeature(dummyFeature));
    }

    @SmackIntegrationTest
    public void testCapsV2Changed(){
        final String dummyFeature = getNewDummyFeature();
        String nodeAlgoHashBefore = EntityCapsManagerV2.getAlgoHashByJid(conTwo.getUser());
        sdmTwo.addFeature(dummyFeature);
        String nodeAlgoHashAfter = EntityCapsManagerV2.getAlgoHashByJid(conTwo.getUser());
        assertFalse(nodeAlgoHashAfter.equals(nodeAlgoHashBefore));
    }

    @SmackIntegrationTest
    public void testEntityCapsV2() throws XMPPException.XMPPErrorException, SmackException.NotConnectedException, InterruptedException, SmackException.NoResponseException, TimeoutException {
        final String dummyFeature = getNewDummyFeature();

        dropWholeEntityCapsCache();

        performActionAndWaitUntilStanzaReceived(new Runnable() {
            @Override
            public void run() {
                sdmTwo.addFeature(dummyFeature);
            }
        }, connection, new AndFilter(PresenceTypeFilter.AVAILABLE, FromMatchesFilter.create(conTwo.getUser())));

        waitUntilTrue(new Condition() {
            @Override
            public boolean evaluate() throws SmackException.NoResponseException, XMPPException.XMPPErrorException, SmackException.NotConnectedException, InterruptedException {
                DiscoverInfo info = sdmOne.discoverInfo(conTwo.getUser());
                return info.containsFeature(dummyFeature);
            }
        });

        DiscoverInfo info = sdmOne.discoverInfo(conTwo.getUser());

        String u1AlgoHash = EntityCapsManagerV2.getAlgoHashByJid(conTwo.getUser());
        assertNotNull(u1AlgoHash);

        DiscoverInfo entityInfo = EntityCapsManagerV2.CAPS_CACHE.lookup(u1AlgoHash);
        assertNotNull(entityInfo);

        assertEquals(info.toXML().toString(), entityInfo.toXML().toString());
    }

    private void dropWholeEntityCapsCache() {
        EntityCapsManagerV2.CAPS_CACHE.clear();
        EntityCapsManagerV2.JID_TO_NODE_ALGOHASH_CACHE.clear();
    }

    private final AtomicInteger dummyFeatureId = new AtomicInteger();
    private final Set<String> dummyFeatures = new HashSet<>();

    private String getNewDummyFeature() {
        String dummyFeature = "entityCapsTest" + dummyFeatureId.incrementAndGet();
        dummyFeatures.add(dummyFeature);
        return dummyFeature;
    }
}
