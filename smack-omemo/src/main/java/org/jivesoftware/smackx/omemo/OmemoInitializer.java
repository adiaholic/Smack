/**
 *
 * Copyright 2017 Paul Schaub
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
package org.jivesoftware.smackx.omemo;

import org.jivesoftware.smack.initializer.UrlInitializer;
import org.jivesoftware.smack.util.SecurityUtil;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Initializer class that registers omemo providers.
 *
 * @author Paul Schaub
 */
@SuppressWarnings("unused")
public class OmemoInitializer extends UrlInitializer {

    static {
        // Remove any BC providers and add a fresh one.
        // This is done, since older Android versions ship with a crippled BC provider.
        SecurityUtil.ensureProviderAtFirstPosition(BouncyCastleProvider.class);
    }

    @Override
    protected String getProvidersUri() {
        return "classpath:org.jivesoftware.smackx.omemo/omemo.providers";
    }

    @Override
    protected String getConfigUri() {
        return "classpath:org.jivesoftware.smackx.omemo/omemo.xml";
    }
}
