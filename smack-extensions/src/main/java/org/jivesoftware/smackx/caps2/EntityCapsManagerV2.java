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

import org.jivesoftware.smack.*;
import org.jivesoftware.smack.filter.*;
import org.jivesoftware.smack.packet.*;
import org.jivesoftware.smack.util.EqualsUtil;
import org.jivesoftware.smack.util.HashCode;
import org.jivesoftware.smackx.caps.EntityCapsManager;
import org.jivesoftware.smackx.caps2.cache.EntityCapsV2PersistentCache;
import org.jivesoftware.smackx.caps2.packet.CapsV2Extension;
import org.jivesoftware.smackx.caps2.packet.HashFunctions;
import org.jivesoftware.smackx.disco.ServiceDiscoveryManager;
import org.jivesoftware.smackx.disco.packet.DiscoverInfo;
import org.jivesoftware.smackx.disco.packet.DiscoverInfoBuilder;
import org.jivesoftware.smackx.disco.packet.DiscoverInfoView;
import org.jivesoftware.smackx.xdata.FormField;
import org.jivesoftware.smackx.xdata.packet.DataForm;
import org.jxmpp.jid.DomainBareJid;
import org.jxmpp.jid.EntityFullJid;
import org.jxmpp.jid.Jid;
import org.jxmpp.util.cache.LruCache;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class EntityCapsManagerV2 extends Manager {

    private static final String FEATURE = CapsV2Extension.NAMESPACE;

    private final ServiceDiscoveryManager sdm;
    private static final Map<XMPPConnection, EntityCapsManagerV2> INSTANCES = new WeakHashMap<>();
    
    @SuppressWarnings("unused")
	private volatile Presence presenceSend;

    private static final Map<String, MessageDigest> SUPPORTED_ALGOS = new HashMap<String, MessageDigest>();
    private static final LruCache<Jid, AlgoHash> JID_TO_NODE_AlgoHash_CACHE = new LruCache<>(10000);

    protected static EntityCapsV2PersistentCache persistentCache;
    // private static String ENTITYNODE = SmackConfiguration.SMACK_URL_STRING;

    private static final StanzaFilter PRESENCES_WITH_CAPS = new AndFilter(new StanzaTypeFilter(Presence.class), new StanzaExtensionFilter(
            CapsV2Extension.ELEMENT, CapsV2Extension.NAMESPACE));

    static final LruCache<String, DiscoverInfo> CAPS_CACHE = new LruCache<>(1000);
    static final LruCache<Jid, EntityCapsManager.NodeVerHash> JID_TO_NODE_ALGOHASH_CACHE = new LruCache<>(10000);

    @SuppressWarnings("unused")
	private static AlgoHash CURRENT_ALGO_HASH;

    private EntityCapsManagerV2(XMPPConnection connection,List <String> algo) throws IOException, NoSuchAlgorithmException {
        super(connection);
        this.sdm = ServiceDiscoveryManager.getInstanceFor(connection);
        INSTANCES.put(connection, this);

        connection.addConnectionListener(new ConnectionListener() {
        	@Override
            public void connected(XMPPConnection connection) {
                // It's not clear when a server would report the caps stream
                // feature, so we try to process it after we are connected and
                // once after we are authenticated.
                processCapsStreamFeatureIfAvailable(connection);
            }
            @Override
            public void authenticated(XMPPConnection connection, boolean resumed) {
                // It's not clear when a server would report the caps stream
                // feature, so we try to process it after we are connected and
                // once after we are authenticated.
                processCapsStreamFeatureIfAvailable(connection);

                // Reset presenceSend when the connection was not resumed
                if (!resumed) {
                    presenceSend = null;
                }
            }
            private void processCapsStreamFeatureIfAvailable(XMPPConnection connection) {
                CapsV2Extension capsV2Extension = connection.getFeature(
                        CapsV2Extension.class);
                if (capsV2Extension == null) {
                    return;
                }
                DomainBareJid from = connection.getXMPPServiceDomain();
                addCapsV2ExtensionInfo(from, capsV2Extension);
            }
		});
        updateLocalEntityCaps(algo);

        connection.addAsyncStanzaListener(new StanzaListener() {
            @Override
            public void processStanza(Stanza packet) throws SmackException.NotConnectedException, InterruptedException, SmackException.NotLoggedInException {
                // CapsV2Extension capsV2Extension = CapsV2Extension.from(packet);

            }
        },PRESENCES_WITH_CAPS);

    }

    public static String getAlgoHashByJid(EntityFullJid user) {
        return null;
    }

    private void updateLocalEntityCaps(List<String> algo) throws IOException, NoSuchAlgorithmException {
        @SuppressWarnings("unused")
		XMPPConnection connection = connection();

        DiscoverInfoBuilder discoverInfoBuilder = DiscoverInfo.builder("synthetized-disco-info-response")
                .ofType(IQ.Type.result);
        sdm.addDiscoverInfoTo(discoverInfoBuilder);

        CURRENT_ALGO_HASH = generateCapabilityHash(discoverInfoBuilder,algo);
    }

    public static AlgoHash generateCapabilityHash(DiscoverInfoView di, List<String> algoList) throws NoSuchAlgorithmException, IOException {

        // Step 1 : Incase of presence of an element other than <identity>, <feature> or ServiceDiscovery Extensions, throw error.

        // Step 2 : If <x> contains a <reported> or <item> element, abort with an error.

        // Step 3 : If <x> does not adhere to "FORM_TYPE" protocol from XEP-0068, abort with an error.

        // Step 4 : Process <feature> elements.
        List<DiscoverInfo.Feature> features = di.getFeatures();

        SortedSet<String> featureSortedSet = new TreeSet<>();

        for(DiscoverInfo.Feature feature : features) {
            featureSortedSet.add(feature.getVar());
        }

        String featureString = "";
        Iterator<String> iterator = featureSortedSet.iterator();
        while (iterator.hasNext()){
            featureString += getHexString(iterator.next());
            featureString += "1f";
        }
        featureString += "1c";


        // Step 5 : Process <identity> elements.
        List<DiscoverInfo.Identity> identities = di.getIdentities();

        SortedSet<String> identitySortedSet = new TreeSet<>();

        for(DiscoverInfo.Identity identity : identities) {
            identitySortedSet.add(getHexString(identity.getCategory()) + "1f"
                                + getHexString(identity.getType()) + "1f"
                                + getHexString(identity.getLanguage()) + "1f"
                                + getHexString(identity.getName()) + "1f"
                                + "1e");
        }

        String identityString = "";
        Iterator<String> iterator1 = identitySortedSet.iterator();
        while (iterator1.hasNext()) {
            identityString += iterator1.next();
        }
        identityString += "1c";

        // Step 6 : Processing of Service Discovery Extensions.
        // @TODO : Add support for multiple service discovery extensions.
        DataForm extendedInfo = DataForm.from(di);
        String extensionString = "";

        if(extendedInfo != null) {
            List<FormField> fields = extendedInfo.getFields();
            Iterator<FormField> formFieldIterator = fields.iterator();

            SortedSet<String> extendedSortedSet = new TreeSet<>();

            while (formFieldIterator.hasNext()) {
                FormField formField = formFieldIterator.next();

                String valuesInField = "";
                SortedSet<String> valueSortedSet = new TreeSet<>();
                List<String> valueStringList = formField.getValuesAsString();
                Iterator<String> valueListIterator = valueStringList.iterator();
                while (valueListIterator.hasNext()) {
                    valueSortedSet.add(getHexString(valueListIterator.next()) + "1f");
                }
                Iterator<String> iterator2 = valueSortedSet.iterator();
                while (iterator2.hasNext()) {
                    valuesInField += iterator2.next();
                }
                valuesInField = getHexString(formField.getFieldName()) + "1f" + valuesInField;
                valuesInField += "1e";
                extendedSortedSet.add(valuesInField);
            }

            Iterator<String> extendedSortedSetIterator = extendedSortedSet.iterator();
            while(extendedSortedSetIterator.hasNext()) {
                extensionString += extendedSortedSetIterator.next();
            }
            extensionString += "1d";
        }
        extensionString += "1c";
        String finalHexString =  featureString + identityString + extensionString;

        byte[] input = DatatypeConverter.parseHexBinary(finalHexString);

        Set<CapsV2Extension.HashBuilder> hashBuilders = HashFunctions.digestIntoBase64(input,algoList);
        return new AlgoHash(hashBuilders);
    }

    private static String getHexString(String attribute) throws UnsupportedEncodingException {
        String str = attribute;
        StringBuffer sb = new StringBuffer();
        if(str!=null){

            byte[] ch = str.getBytes("utf8");
            String hexString;

            for(int i=0;i<ch.length;i++) {
                if(ch[i] < 0 ){
                    hexString = Integer.toHexString(ch[i]);
                    int lastIndexOf_d = hexString.lastIndexOf("f");
                    hexString = hexString.substring(lastIndexOf_d + 1);
                }
                else{
                    hexString = Integer.toHexString(ch[i]);
                }
                sb.append(hexString);
            }
        }
        return sb.toString();
    }

    public static void setPersistentCache(EntityCapsV2PersistentCache cache) {
        persistentCache = cache;
    }

    public static void addDiscoverInfoByNode(String algoHash, DiscoverInfo di) {
        CAPS_CACHE.put(algoHash, di);

        if (persistentCache != null)
            persistentCache.addDiscoverInfoByNodePersistent(algoHash, di);
    }

    public static DiscoverInfo getDiscoveryInfoBy(String nodeAlgohash) {
        DiscoverInfo info = CAPS_CACHE.lookup(nodeAlgohash);

        // If it was not in CAPS_CACHE, try to retrieve the information from persistentCache
        if (info == null && persistentCache != null) {
            info = persistentCache.lookup(nodeAlgohash);
            // Promote the information to CAPS_CACHE if one was found
            if (info != null) {
                CAPS_CACHE.put(nodeAlgohash, info);
            }
        }

        // If we were able to retrieve information from one of the caches, copy it before returning
        if (info != null)
            info = new DiscoverInfo(info);

        return info;
    }

    private static void addCapsV2ExtensionInfo(DomainBareJid from, CapsV2Extension capsV2Extension) {
        Set<CapsV2Extension.HashBuilder> hashes = capsV2Extension.getHASHES();
        for (CapsV2Extension.HashBuilder hashBuilder : hashes) {

            String hashInUppercase = hashBuilder.getAlgo();

            // SUPPORTED_HASHES uses the format of MessageDigest, which is uppercase, e.g. "SHA-1" instead of "sha-1"
            if (!SUPPORTED_ALGOS.containsKey(hashInUppercase))
                return;

            // String algo = hashInUppercase.toLowerCase(Locale.US);
            JID_TO_NODE_AlgoHash_CACHE.put(from,new AlgoHash(capsV2Extension.getHASHES()));
        }
    }

    public static EntityCapsManagerV2 getInstanceFor(AbstractXMPPConnection connection, List<String> hashExpected) throws IOException, NoSuchAlgorithmException {
        if (SUPPORTED_ALGOS.size() == 0 ) {
            throw new IllegalStateException("No supported hashes for EntityCapsManager");
        }
        EntityCapsManagerV2 entityCapsManagerV2 = INSTANCES.get(connection);
        if (entityCapsManagerV2 == null) {
            entityCapsManagerV2 = new EntityCapsManagerV2(connection,null);
        }
        return entityCapsManagerV2;
    }

    // private void broadcastEntityCapabilities(CapsV2Extension capsV2Extension) {
        // Presence presence = new Presence(new PresenceBuilder("entitycapsV2 broadcast"))
    // }

    @SuppressWarnings("unused")
	private static boolean verifyCapabilityHashSet(AlgoHash nodeAlgoHash, DiscoverInfo discoverInfo,List<String> algoList) throws IOException, NoSuchAlgorithmException {
        AlgoHash algoHash1 = generateCapabilityHash(discoverInfo,algoList);
        boolean verified = nodeAlgoHash.equals(algoHash1);
        if (verified) {
            addToCapabilityHashCache();
        }
        return verified;
    }


    private static void addToCapabilityHashCache() {
    }

    public String generateCapabilityHashNodes(String algo) {

        /**
         * The Capability Hash Node is obtained from a Capability Hash with the following simple algorithm:
         *
         * To the namespace prefix "urn:xmpp:caps#", append the name of the hash function as per Use of Cryptographic Hash Functions in XMPP (XEP-0300) [9].
         * Append a FULL STOP character (U+002E, ".").
         * Append the Base64 encoded (as specified in RFC 3548 [14]) hash value.
         */

        String CAPABILITY_HASH_NODE = FEATURE + "#" + algo + "." + HashFunctions.getBase64HashForAlgo(algo);
        return CAPABILITY_HASH_NODE;
    }

    public boolean isSupported(Jid jid) throws XMPPException.XMPPErrorException, SmackException.NotConnectedException, InterruptedException, SmackException.NoResponseException {
        return sdm.supportsFeature(jid, FEATURE);
    }

    public void advertiseSupport(){
        sdm.addFeature(FEATURE);
    }

    public static class AlgoHash{
        private Map<String,String> algoHash;

        @Override
        public boolean equals(Object o) {
          return EqualsUtil.equals(this,o,
                  (equalBuilder,otherNodeAlgoHash) -> {
                        Set<Map.Entry<String,String>> otherAlgoHashSet = otherNodeAlgoHash.getAlgoHash().entrySet();

                        for (Map.Entry<String,String> entry : otherAlgoHashSet) {
                            equalBuilder.append(entry.getValue(),algoHash.get(entry.getKey()));
                        }
          });
        }

        @Override
        public int hashCode() {
            Set<Map.Entry<String,String>> algoHashSet = algoHash.entrySet();
            HashCode.Builder builder = HashCode.builder();
            for (Map.Entry<String,String> entry : algoHashSet) {
                builder.append(entry.getKey())
                        .append(entry.getValue());
            }
            return builder.build();
        }

        AlgoHash(Set<CapsV2Extension.HashBuilder> hashes){
            algoHash = new HashMap<>();
            for(CapsV2Extension.HashBuilder builder : hashes) {
                algoHash.put(builder.getAlgo(),builder.getHash());
            }
        }
        public Map<String, String> getAlgoHash() {
            return algoHash;
        }

        public String getHashForAlgo(String algo){
            return algoHash.get(algo);
        }
    }
}
