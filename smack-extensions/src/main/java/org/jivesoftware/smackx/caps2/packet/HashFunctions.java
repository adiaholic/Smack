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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class HashFunctions {

    private static List<String> IANA_ALGORITHMS = Arrays.asList("md2","md5","sha-1","sha-224","sha-256",
            "sha-384", "sha-512", "shake128", "shake256");

    private static List<String> ADDITIONAL_ALGORITHMS = Arrays.asList("sha3-256","sha3-512","blake2b-256",
            "blake2b-512");

    private static List<String> IMPLEMENT_ALGORITHMS = new ArrayList<>();

    private static HashMap<String,String> ALGO_HASH_MAP = new HashMap<>();

    public static boolean addAlgorithm(String algo) {
        String algoInLowerCase = algo.toLowerCase();
        if (IANA_ALGORITHMS.contains(algoInLowerCase) || ADDITIONAL_ALGORITHMS.contains(algoInLowerCase)) {
            return IMPLEMENT_ALGORITHMS.add(algoInLowerCase);
        }
        throw new IllegalStateException("DO NOT include any hash functions which MUST NOT be supported according to XEP-0300");
    }

    public static boolean removeAlgorithm(String algo) {
        String algoInLowerCase = algo.toLowerCase();
        return IMPLEMENT_ALGORITHMS.remove(algoInLowerCase);
    }

    public static void clearAllAlgorithms(){
        IMPLEMENT_ALGORITHMS.clear();
    }

    public static Set<CapsV2Extension.HashBuilder> digestIntoBase64(byte[] bytes,List<String> algoList) throws NoSuchAlgorithmException {
        IMPLEMENT_ALGORITHMS = algoList;
        if(IMPLEMENT_ALGORITHMS.isEmpty()){
            throw new IllegalStateException("The set of hash functions MUST include at least one hash function according to XEP-0300.");
        }
        Set<CapsV2Extension.HashBuilder> builderSet = new HashSet<>();

        for (String algo : IMPLEMENT_ALGORITHMS) {
            CapsV2Extension.HashBuilder builder = new CapsV2Extension.HashBuilder();
            String base64Hash;
            if (algo.toLowerCase().contentEquals("sha3-256")) {
                // SHA3.DigestSHA3 sha3 = new SHA3.Digest256();
                // sha3.update(bytes);
                // base64Hash = Base64.getEncoder().encodeToString(sha3.digest());
            	throw new IllegalArgumentException("Find an alternative to bouncy castle");
            }
            else {
                MessageDigest messageDigest = MessageDigest.getInstance(algo);
                byte[] digest = messageDigest.digest(bytes);
                base64Hash = Base64.getEncoder().encodeToString(digest);
            }
            builder.setAlgo(algo);
            builder.setHash(base64Hash);
            builderSet.add(builder);
            ALGO_HASH_MAP.put(algo,base64Hash);
        }
        return builderSet;
    }

    public static String getBase64HashForAlgo(String algo) {
        return ALGO_HASH_MAP.get(algo);
    }
}
