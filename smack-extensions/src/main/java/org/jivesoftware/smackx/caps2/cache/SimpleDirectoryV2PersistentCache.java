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
package org.jivesoftware.smackx.caps2.cache;

import org.jivesoftware.smack.util.PacketParserUtils;
import org.jivesoftware.smack.util.stringencoder.Base32;
import org.jivesoftware.smack.util.stringencoder.StringEncoder;
import org.jivesoftware.smackx.caps.cache.SimpleDirectoryPersistentCache;
import org.jivesoftware.smackx.disco.packet.DiscoverInfo;

import java.io.*;
import java.util.logging.Level;
import java.util.logging.Logger;

public class SimpleDirectoryV2PersistentCache implements EntityCapsV2PersistentCache {

    private final File cacheDir;
    private final StringEncoder<String> filenameEncoder;

    private static final Logger LOGGER = Logger.getLogger(SimpleDirectoryPersistentCache.class.getName());

    public SimpleDirectoryV2PersistentCache(File cacheDir){
        this(cacheDir, Base32.getStringEncoder());
    }

    public SimpleDirectoryV2PersistentCache(File cacheDir, StringEncoder<String> filenameEncoder) {
        if (!cacheDir.exists())
            throw new IllegalStateException("Cache directory \"" + cacheDir + "\" does not exist");
        if (!cacheDir.isDirectory())
            throw new IllegalStateException("Cache directory \"" + cacheDir + "\" is not a directory");

        this.cacheDir = cacheDir;
        this.filenameEncoder = filenameEncoder;
    }

    @Override
    public void addDiscoverInfoByNodePersistent(String nodeVer, DiscoverInfo info) {
        File nodeFile = getFileFor(nodeVer);
        try {
            if (nodeFile.createNewFile())
                writeInfoToFile(nodeFile, info);
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Failed to write disco info to file", e);
        }
    }

    @Override
    public DiscoverInfo lookup(String nodeVer) {
        File nodeFile = getFileFor(nodeVer);
        if (!nodeFile.isFile()) {
            return null;
        }
        DiscoverInfo info = null;
        try {
            info = restoreInfoFromFile(nodeFile);
        }
        catch (Exception e) {
            LOGGER.log(Level.WARNING, "Coud not restore info from file", e);
        }
        return info;
    }
    private File getFileFor(String nodeVer) {
        String filename = filenameEncoder.encode(nodeVer);
        return new File(cacheDir, filename);
    }

    private static void writeInfoToFile(File file, DiscoverInfo info) throws IOException {
        try (DataOutputStream dos = new DataOutputStream(new FileOutputStream(file))) {
            dos.writeUTF(info.toXML().toString());
        }
    }

    private static DiscoverInfo restoreInfoFromFile(File file) throws Exception {
        String fileContent;
        try (DataInputStream dis = new DataInputStream(new FileInputStream(file))) {
            fileContent = dis.readUTF();
        }
        if (fileContent == null) {
            return null;
        }
        return PacketParserUtils.parseStanza(fileContent);
    }

    @Override
    public void emptyCache() {
        File[] files = cacheDir.listFiles();
        if (files == null) {
            return;
        }
        for (File f : files) {
            f.delete();
        }
    }
}
