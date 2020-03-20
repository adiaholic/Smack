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
package org.jivesoftware.smackx.caps2;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

import java.util.*;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jivesoftware.smack.*;
import org.jivesoftware.smack.packet.IQ;
import org.jivesoftware.smack.packet.Presence;
import org.jivesoftware.smack.util.EqualsUtil;
import org.jivesoftware.smack.util.HashCode;
import org.jivesoftware.smackx.caps.cache.EntityCapsPersistentCache;
import org.jivesoftware.smackx.caps2.packet.CapsV2Extension;
import org.jivesoftware.smackx.disco.AbstractNodeInformationProvider;
import org.jivesoftware.smackx.disco.DiscoInfoLookupShortcutMechanism;
import org.jivesoftware.smackx.disco.ServiceDiscoveryManager;
import org.jivesoftware.smackx.disco.packet.DiscoverInfo;

import org.jivesoftware.smackx.disco.packet.DiscoverInfoBuilder;
import org.jivesoftware.smackx.disco.packet.DiscoverInfoView;
import org.jivesoftware.smackx.xdata.FormField;
import org.jivesoftware.smackx.xdata.packet.DataForm;

import org.jxmpp.jid.DomainBareJid;
import org.jxmpp.jid.Jid;
import org.jxmpp.util.cache.LruCache;

public class EntityCapsManagerV2 extends Manager {

    // Declaring entities for this class
    public static Map<XMPPConnection, EntityCapsManagerV2> INSTANCES = new HashMap<>();
    private final ServiceDiscoveryManager sdm;
    private volatile Presence presenceSend;
    private List<String> currentSupportAlgos = new ArrayList<>();
    private NodeAlgoHash currentNodeAlgoHash;
    private static String defaultAlgo;
    private final Queue<NodeAlgoHash> lastLocalCapsAlgoHashes = new ConcurrentLinkedQueue<>();

    // Declaring caches
    // CAPS_CACHE : < NodeAlgoHash , DiscoverInfo >
    static final LruCache<String, DiscoverInfo> CAPS_CACHE = new LruCache<>(1000);
    // JID_TO_NODE_ALGOHASH_CACHE : < JID , NodeAlgoHash >
    static final LruCache<Jid, EntityCapsManagerV2.NodeAlgoHash> JID_TO_NODE_ALGOHASH_CACHE = new LruCache<>(10000);
    protected static EntityCapsPersistentCache persistentCache;

    static {
        XMPPConnectionRegistry.addConnectionCreationListener(new ConnectionCreationListener() {
            @Override
            public void connectionCreated(XMPPConnection connection) {
                getInstancecFor(connection);
            }
        });

        // What should the prority be set as ?
        ServiceDiscoveryManager.addDiscoInfoLookupShortcutMechanism(new DiscoInfoLookupShortcutMechanism("XEP-0390: Entity Capabilities", 500) {
            @Override
            public DiscoverInfo getDiscoverInfoByUser(ServiceDiscoveryManager serviceDiscoveryManager, Jid jid) {
                DiscoverInfo info = EntityCapsManagerV2.getDiscoverInfoByUser(jid);
                if (info != null) {
                    return info;
                }

                NodeAlgoHash nodeAlgoHash = getNodeAlgoHashByJid(jid);
                if (nodeAlgoHash == null) {
                    return null;
                }

                Set<String> supportedAlgos = nodeAlgoHash.supportedAlgos;
                Iterator<String> algoIterator = supportedAlgos.iterator();

                while (algoIterator.hasNext()) {
                    try {
                        info = serviceDiscoveryManager.discoverInfo(jid,nodeAlgoHash.getHashForAlgo(algoIterator.next()));
                    } catch (SmackException.NoResponseException | XMPPException.XMPPErrorException | SmackException.NotConnectedException | InterruptedException e) {
                        // Log
                        return null;
                    }
                    if (info != null) {
                        break;
                    }
                }

                algoIterator.remove();
                algoIterator = supportedAlgos.iterator();

                if (verifyDiscoverInfoAlgoHash(nodeAlgoHash.getAlgoHash(),info)) {
                    addDiscoverInfoByNode(nodeAlgoHash.getNodeAlgoHashForAlgo(algoIterator.next()),info);
                } else {
                    // Log
                }
                return info;
            }
        });
    }

    private EntityCapsManagerV2(XMPPConnection connection) {
        super(connection);
        this.sdm = ServiceDiscoveryManager.getInstanceFor(connection);
        INSTANCES.put(connection,this);

        connection.addConnectionListener(new AbstractConnectionListener() {
            @Override
            public void connected(XMPPConnection connection) {
                processCapsStreamFeatureIfAvailable(connection);
            }

            @Override
            public void authenticated(XMPPConnection connection, boolean resumed) {
                processCapsStreamFeatureIfAvailable(connection);

                if (!resumed) {
                    presenceSend = null;
                }
            }
            private void processCapsStreamFeatureIfAvailable(XMPPConnection connection) {
                CapsV2Extension capsV2Extension = connection.getFeature(CapsV2Extension.ELEMENT,CapsV2Extension.NAMESPACE);
                if(capsV2Extension == null) {
                    return;
                }
                DomainBareJid from = connection.getXMPPServiceDomain();
                addCapsExtensionInfo(from,capsV2Extension);
            }
        });

        updateLocalEntityCaps();

    }

    private void updateLocalEntityCaps() {
        XMPPConnection connection = connection();
        DiscoverInfoBuilder discoverInfoBuilder = DiscoverInfo.builder("synthetized-disco-info-response")
                .ofType(IQ.Type.result);
        sdm.addDiscoverInfoTo(discoverInfoBuilder);
        NodeAlgoHash currentNodeAlgoHash = null;
        try {
            currentNodeAlgoHash = generateCapabilityHash(discoverInfoBuilder,currentSupportAlgos);
        } catch (NoSuchAlgorithmException | IOException e) {
            // Log
        }

        final Map<String, String> localNodeAlgoHashSet = getLocalNodeAlgoHash();
        String localNodeAlgoHash = localNodeAlgoHashSet.get(defaultAlgo);
        discoverInfoBuilder.setNode(localNodeAlgoHash);

        final DiscoverInfo discoverInfo = discoverInfoBuilder.build();
        addDiscoverInfoByNode(localNodeAlgoHash,discoverInfo);

        if (lastLocalCapsAlgoHashes.size() > 10) {
            NodeAlgoHash oldNodeAlgoHash = lastLocalCapsAlgoHashes.poll();
            sdm.removeNodeInformationProvider(oldNodeAlgoHash.getNodeAlgoHashForAlgo(defaultAlgo));
        }
        lastLocalCapsAlgoHashes.add(currentNodeAlgoHash);

        if(connection != null) {
            JID_TO_NODE_ALGOHASH_CACHE.put(connection.getUser(),currentNodeAlgoHash);
        }

        final List<DiscoverInfo.Identity> identities = new LinkedList<>(ServiceDiscoveryManager.getInstanceFor(connection).getIdentities());
        sdm.setNodeInformationProvider(localNodeAlgoHash, new AbstractNodeInformationProvider() {
            List<String> features = sdm.getFeatures();
            List<DataForm> extendedInfoList = sdm.getExtendedInfo();
            @Override
            public List<String> getNodeFeatures() {
                return features;
            }

            @Override
            public List<DiscoverInfo.Identity> getNodeIdentities() {
                return identities;
            }

            @Override
            public List<DataForm> getNodePacketExtensions() {
                return extendedInfoList;
            }
        });

        if (connection != null && connection.isAuthenticated() && presenceSend != null) {
            try {
                connection.sendStanza(presenceSend.cloneWithNewId());
            }
            catch (InterruptedException | SmackException.NotConnectedException e) {
                Logger.getAnonymousLogger().log(Level.WARNING, "Could could not update presence with caps info", e);
            }
        }
    }

    private Map<String, String> getLocalNodeAlgoHash() {
        return currentNodeAlgoHash.getAllNodeAlgoHashes();
    }

    private static void addCapsExtensionInfo(DomainBareJid from, CapsV2Extension capsV2Extension) {
        Set<CapsV2Extension.HashElement> HASHES = capsV2Extension.getHASHES();
        List<CapsV2Extension.HashElement> list = new ArrayList<>();
        list.addAll(HASHES);

        Iterator<CapsV2Extension.HashElement> iterator = list.iterator();

        Set<CapsV2Extension.HashElement> newHashes = new HashSet<>();
        while (iterator.hasNext()) {
            CapsV2Extension.HashElement hashElement = iterator.next();
            String capsV2ExtensionHash = hashElement.getHash();
            String hashInLowerCase = capsV2ExtensionHash.toLowerCase(Locale.US);

            if (!HashFunctions.isAlgoSupported(hashInLowerCase)) {
                return;
            }
            newHashes.add(hashElement);
        }
        JID_TO_NODE_ALGOHASH_CACHE.put(from,new NodeAlgoHash(newHashes));
    }

    private static void addDiscoverInfoByNode(String nodeAlgoHashForAlgo, DiscoverInfo info) {
        CAPS_CACHE.put(nodeAlgoHashForAlgo,info);
        if (persistentCache != null) {
            persistentCache.addDiscoverInfoByNodePersistent(nodeAlgoHashForAlgo,info);
        }
    }

    public static synchronized EntityCapsManagerV2 getInstancecFor(XMPPConnection connection) {
        EntityCapsManagerV2 entityCapsManagerV2 = INSTANCES.get(connection);
        if (entityCapsManagerV2 == null) {
            entityCapsManagerV2 = new EntityCapsManagerV2(connection);
        }
        return entityCapsManagerV2;
    }

    private static boolean verifyDiscoverInfoAlgoHash(Map<String, String> algoHash, DiscoverInfo info) {
        List<String> algoList = new ArrayList<>();
        algoList.addAll(algoHash.keySet());

        NodeAlgoHash nodeAlgoHash = null;
        try {
            nodeAlgoHash = generateCapabilityHash(info,algoList);
        } catch (NoSuchAlgorithmException | IOException e) {
            // Log
        }

        Iterator<String> supportedAlgosIterator = algoList.iterator();
        while (supportedAlgosIterator.hasNext()) {
            String algo = supportedAlgosIterator.next();
            if (!algoHash.get(algo).equals(nodeAlgoHash.getHashForAlgo(algo))){
                return false;
            }
        }
        return true;
    }

    private static NodeAlgoHash getNodeAlgoHashByJid(Jid jid) {
        return JID_TO_NODE_ALGOHASH_CACHE.lookup(jid);
    }

    private static DiscoverInfo getDiscoverInfoByUser(Jid jid) {
        NodeAlgoHash nodeAlgoHash = JID_TO_NODE_ALGOHASH_CACHE.lookup(jid);
        if (nodeAlgoHash == null) {
            return null;
        }
        Set<String> supportedAlgos = nodeAlgoHash.getSupportedAlgos();
        DiscoverInfo info = null;
        for (String algo : supportedAlgos) {
            info = getDiscoverInfoByNodeAlgoHash(nodeAlgoHash.generateNodeAlgoHash(algo));
            if (info != null){
                break;
            }
        }
        return info;
    }

    private static DiscoverInfo getDiscoverInfoByNodeAlgoHash(String nodeAlgoHash) {
        DiscoverInfo info = CAPS_CACHE.lookup(nodeAlgoHash);

        if (info == null && persistentCache != null) {
            info = persistentCache.lookup(nodeAlgoHash);
            if (info != null) {
                CAPS_CACHE.put(nodeAlgoHash,info);
            }
        }

        if (info != null) {
            CAPS_CACHE.put(nodeAlgoHash,info);
        }
        return info;
    }

    public static NodeAlgoHash generateCapabilityHash(DiscoverInfoView di, List<String> algoList) throws NoSuchAlgorithmException, IOException {

        if(algoList.size() == 0) {
            algoList.add(defaultAlgo);
        }
        // Step 1 : Incase of presence of an element other than <identity>, <feature> or ServiceDiscovery Extensions, throw error.

        // Step 2 : If <x> contains a <reported> or <item> element, abort with an error.
        DataForm extendedInfo = DataForm.from(di);
        if( extendedInfo != null ) {
            if (extendedInfo.getItems().size() != 0 || extendedInfo.getReportedData() != null) {
                throw new IllegalArgumentException(" <x> should not contain a <reported> or <item> element");
            }
        }

        // Step 3 : If <x> does not adhere to "FORM_TYPE" protocol from XEP-0068, abort with an error.

        // Step 4 : Process <feature> elements.
        List<DiscoverInfo.Feature> features = di.getFeatures();

        SortedSet<String> featureSortedSet = new TreeSet<>();

        for (DiscoverInfo.Feature feature : features) {
            featureSortedSet.add(feature.getVar());
        }

        String featureString = "";
        Iterator<String> iterator = featureSortedSet.iterator();
        while (iterator.hasNext()) {
            featureString += getHexString(iterator.next());
            featureString += "1f";
        }
        featureString += "1c";


        // Step 5 : Process <identity> elements.
        List<DiscoverInfo.Identity> identities = di.getIdentities();

        SortedSet<String> identitySortedSet = new TreeSet<>();

        for (DiscoverInfo.Identity identity : identities) {
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

        String extensionString = "";

        if (extendedInfo != null) {
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
                valuesInField = getHexString(formField.getVariable()) + "1f" + valuesInField;
                valuesInField += "1e";
                extendedSortedSet.add(valuesInField);
            }

            Iterator<String> extendedSortedSetIterator = extendedSortedSet.iterator();
            while (extendedSortedSetIterator.hasNext()) {
                extensionString += extendedSortedSetIterator.next();
            }
            extensionString += "1d";
        }
        extensionString += "1c";
        String finalHexString =  featureString + identityString + extensionString;

        // byte[] input = DatatypeConverter.parseHexBinary(finalHexString);
        // byte[] input = Hex.decodeHex(finalHexString.toCharArray());
        byte[] input = hexStringToByteArray(finalHexString);
        Set<CapsV2Extension.HashElement> hashElements = HashFunctions.digest(input, algoList);
        return new NodeAlgoHash(hashElements);
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private static String getHexString(String attribute) throws UnsupportedEncodingException {
        String str = attribute;
        StringBuffer sb = new StringBuffer();
        if (str != null) {

            byte[] ch = str.getBytes("UTF-8");
            String hexString;

            for (int i = 0; i < ch.length; i++) {
                if (ch[i] < 0) {
                    hexString = Integer.toHexString(ch[i]);
                    int lastIndexOf_d = hexString.lastIndexOf("f");
                    hexString = hexString.substring(lastIndexOf_d + 1);
                }
                else {
                    hexString = Integer.toHexString(ch[i]);
                }
                sb.append(hexString);
            }
        }
        return sb.toString();
    }

    public static class NodeAlgoHash{
        // map < algo, hash >
        private Map<String, String> algoHash;

        // map < algo, nodeAlgoHash >
        private Map<String,String > nodeAlgoHash;

        private Set<String> supportedAlgos;

        @Override
        public boolean equals(Object o) {
            return EqualsUtil.equals(this, o,
                    (equalBuilder, otherNodeAlgoHash) -> {
                        Set<Map.Entry<String, String>> otherAlgoHashSet = otherNodeAlgoHash.getAlgoHash().entrySet();

                        for (Map.Entry<String, String> entry : otherAlgoHashSet) {
                            equalBuilder.append(entry.getValue(), algoHash.get(entry.getKey()));
                        }
                    });
        }

        @Override
        public int hashCode() {
            Set<Map.Entry<String, String>> algoHashSet = algoHash.entrySet();
            HashCode.Builder builder = HashCode.builder();
            for (Map.Entry<String, String> entry : algoHashSet) {
                builder.append(entry.getKey())
                        .append(entry.getValue());
            }
            return builder.build();
        }

        NodeAlgoHash(Set<CapsV2Extension.HashElement> hashes) {
            algoHash = new HashMap<>();
            nodeAlgoHash = new HashMap<>();
            supportedAlgos = new HashSet<>();
            for (CapsV2Extension.HashElement hashElement : hashes) {
                algoHash.put(hashElement.getAlgo(), hashElement.getHash());
                nodeAlgoHash.put(hashElement.getAlgo(),generateNodeAlgoHash(hashElement.getAlgo()));
                supportedAlgos.add(hashElement.getAlgo());
            }
        }

        private String generateNodeAlgoHash(String algo) {
            return CapsV2Extension.NAMESPACE + "#" + algo + "." + algoHash.get(algo);
        }

        public Map<String, String> getAlgoHash() {
            return algoHash;
        }

        public Map<String, String> getAllNodeAlgoHashes(){
            return nodeAlgoHash;
        }

        public String getNodeAlgoHashForAlgo(String algo) {
            return nodeAlgoHash.get(algo);
        }

        public String getHashForAlgo(String algo) {
            return algoHash.get(algo);
        }
        public Set<String> getSupportedAlgos(){
            return supportedAlgos;
        }
    }
}
