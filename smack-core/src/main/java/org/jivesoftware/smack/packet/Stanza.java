/**
 *
 * Copyright 2003-2007 Jive Software.
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

package org.jivesoftware.smack.packet;

import static org.jivesoftware.smack.util.StringUtils.requireNotNullOrEmpty;

import org.jivesoftware.smack.packet.id.StanzaIdUtil;
import org.jivesoftware.smack.util.MultiMap;
import org.jivesoftware.smack.util.PacketUtil;
import org.jivesoftware.smack.util.XmlStringBuilder;
import org.jxmpp.util.XmppStringUtils;

import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Base class for XMPP Stanzas, which are called Packet in older versions of Smack (i.e. &lt; 4.1).
 * <p>
 * Every stanza has a unique ID (which is automatically generated, but can be overridden). Stanza
 * IDs are required for IQ stanzas and recommended for presence and message stanzas. Optionally, the
 * "to" and "from" fields can be set.
 * </p>
 * <p>
 * XMPP Stanzas are {@link Message}, {@link IQ} and {@link Presence}. Which therefore subclass this
 * class. <b>If you think you need to subclass this class, then you are doing something wrong.</b>
 * </p>
 *
 * @author Matt Tucker
 * @see <a href="http://xmpp.org/rfcs/rfc6120.html#stanzas">RFC 6120 § 8. XML Stanzas</a>
 */
public abstract class Stanza implements TopLevelStreamElement {

    public static final String TEXT = "text";
    public static final String ITEM = "item";

    protected static final String DEFAULT_LANGUAGE =
            java.util.Locale.getDefault().getLanguage().toLowerCase(Locale.US);

    private final MultiMap<String, PacketExtension> packetExtensions = new MultiMap<>();

    private String id = null;
    private String to = null;
    private String from = null;
    private XMPPError error = null;

    /**
     * Optional value of the 'xml:lang' attribute of the outermost element of
     * the stanza.
     * <p>
     * Such an attribute is defined for all stanza types. For IQ, see for
     * example XEP-50 3.7:
     * "The requester SHOULD provide its locale information using the "xml:lang
     * " attribute on either the <iq/> (RECOMMENDED) or <command/> element."
     * </p>
     */
    protected String language;

    public Stanza() {
        this(StanzaIdUtil.newStanzaId());
    }

    public Stanza(String stanzaId) {
        setStanzaId(stanzaId);
    }

    public Stanza(Stanza p) {
        id = p.getStanzaId();
        to = p.getTo();
        from = p.getFrom();
        error = p.error;

        // Copy extensions
        for (PacketExtension pe : p.getExtensions()) {
            addExtension(pe);
        }
    }

    /**
     * Returns the unique ID of the stanza. The returned value could be <code>null</code>.
     *
     * @return the packet's unique ID or <code>null</code> if the id is not available.
     */
    public String getStanzaId() {
        return id;
    }

    /**
     * 
     * @return the stanza id.
     * @deprecated use {@link #getStanzaId()} instead.
     */
    @Deprecated
    public String getPacketID() {
        return getStanzaId();
    }

    /**
     * Sets the unique ID of the packet. To indicate that a packet has no id
     * pass <code>null</code> as the packet's id value.
     *
     * @param id the unique ID for the packet.
     */
    public void setStanzaId(String id) {
        this.id = id;
    }

    /**
     * 
     * @param packetID
     * @deprecated use {@link #setStanzaId(String)} instead.
     */
    @Deprecated
    public void setPacketID(String packetID) {
        setStanzaId(packetID);
    }

    /**
     * Returns who the packet is being sent "to", or <tt>null</tt> if
     * the value is not set. The XMPP protocol often makes the "to"
     * attribute optional, so it does not always need to be set.<p>
     *
     * @return who the packet is being sent to, or <tt>null</tt> if the
     *      value has not been set.
     */
    public String getTo() {
        return to;
    }

    /**
     * Sets who the packet is being sent "to". The XMPP protocol often makes
     * the "to" attribute optional, so it does not always need to be set.
     *
     * @param to who the packet is being sent to.
     */
    public void setTo(String to) {
        this.to = to;
    }

    /**
     * Returns who the packet is being sent "from" or <tt>null</tt> if
     * the value is not set. The XMPP protocol often makes the "from"
     * attribute optional, so it does not always need to be set.<p>
     *
     * @return who the packet is being sent from, or <tt>null</tt> if the
     *      value has not been set.
     */
    public String getFrom() {
        return from;
    }

    /**
     * Sets who the packet is being sent "from". The XMPP protocol often
     * makes the "from" attribute optional, so it does not always need to
     * be set.
     *
     * @param from who the packet is being sent to.
     */
    public void setFrom(String from) {
        this.from = from;
    }

    /**
     * Returns the error associated with this packet, or <tt>null</tt> if there are
     * no errors.
     *
     * @return the error sub-packet or <tt>null</tt> if there isn't an error.
     */
    public XMPPError getError() {
        return error;
    }

    /**
     * Sets the error for this packet.
     *
     * @param error the error to associate with this packet.
     */
    public void setError(XMPPError error) {
        this.error = error;
    }

    /**
     * Returns the xml:lang of this Stanza, or null if one has not been set.
     *
     * @return the xml:lang of this Stanza, or null.
     */
    public String getLanguage() {
        return language;
    }

    /**
     * Sets the xml:lang of this Stanza.
     *
     * @param language the xml:lang of this Stanza.
     */
    public void setLanguage(String language) {
        this.language = language;
    }

    /**
     * Returns a copy of the packet extensions attached to the packet.
     *
     * @return the packet extensions.
     */
    public List<PacketExtension> getExtensions() {
        synchronized (packetExtensions) {
            return packetExtensions.values();
        }
    }

    /**
     * Return a set of all extensions with the given element name <emph>and</emph> namespace.
     * <p>
     * Changes to the returned set will update the packet extensions, if the returned set is not the empty set.
     * </p>
     *
     * @param elementName the element name, must not be null.
     * @param namespace the namespace of the element(s), must not be null.
     * @return a set of all matching extensions.
     * @since 4.1
     */
    public Set<PacketExtension> getExtensions(String elementName, String namespace) {
        requireNotNullOrEmpty(elementName, "elementName must not be null or empty");
        requireNotNullOrEmpty(namespace, "namespace must not be null or empty");
        String key = XmppStringUtils.generateKey(elementName, namespace);
        return packetExtensions.getAll(key);
    }

    /**
     * Returns the first extension of this packet that has the given namespace.
     * <p>
     * When possible, use {@link #getExtension(String,String)} instead.
     * </p>
     *
     * @param namespace the namespace of the extension that is desired.
     * @return the packet extension with the given namespace.
     */
    public PacketExtension getExtension(String namespace) {
        return PacketUtil.extensionElementFrom(getExtensions(), null, namespace);
    }

    /**
     * Returns the first packet extension that matches the specified element name and
     * namespace, or <tt>null</tt> if it doesn't exist. If the provided elementName is null,
     * only the namespace is matched. Packet extensions are
     * are arbitrary XML sub-documents in standard XMPP packets. By default, a 
     * DefaultPacketExtension instance will be returned for each extension. However, 
     * PacketExtensionProvider instances can be registered with the 
     * {@link org.jivesoftware.smack.provider.ProviderManager ProviderManager}
     * class to handle custom parsing. In that case, the type of the Object
     * will be determined by the provider.
     *
     * @param elementName the XML element name of the packet extension. (May be null)
     * @param namespace the XML element namespace of the packet extension.
     * @return the extension, or <tt>null</tt> if it doesn't exist.
     */
    @SuppressWarnings("unchecked")
    public <PE extends PacketExtension> PE getExtension(String elementName, String namespace) {
        if (namespace == null) {
            return null;
        }
        String key = XmppStringUtils.generateKey(elementName, namespace);
        PacketExtension packetExtension;
        synchronized (packetExtensions) {
            packetExtension = packetExtensions.getFirst(key);
        }
        if (packetExtension == null) {
            return null;
        }
        return (PE) packetExtension;
    }

    /**
     * Adds a packet extension to the packet. Does nothing if extension is null.
     *
     * @param extension a packet extension.
     */
    public void addExtension(PacketExtension extension) {
        if (extension == null) return;
        String key = XmppStringUtils.generateKey(extension.getElementName(), extension.getNamespace());
        synchronized (packetExtensions) {
            packetExtensions.put(key, extension);
        }
    }

    /**
     * Adds a collection of packet extensions to the packet. Does nothing if extensions is null.
     * 
     * @param extensions a collection of packet extensions
     */
    public void addExtensions(Collection<PacketExtension> extensions) {
        if (extensions == null) return;
        for (PacketExtension packetExtension : extensions) {
            addExtension(packetExtension);
        }
    }

    /**
     * Check if a packet extension with the given element and namespace exists.
     * <p>
     * The argument <code>elementName</code> may be null.
     * </p>
     *
     * @param elementName
     * @param namespace
     * @return true if a packet extension exists, false otherwise.
     */
    public boolean hasExtension(String elementName, String namespace) {
        if (elementName == null) {
            return hasExtension(namespace);
        }
        String key = XmppStringUtils.generateKey(elementName, namespace);
        synchronized (packetExtensions) {
            return packetExtensions.containsKey(key);
        }
    }

    /**
     * Check if a packet extension with the given namespace exists.
     * 
     * @param namespace
     * @return true if a packet extension exists, false otherwise.
     */
    public boolean hasExtension(String namespace) {
        synchronized (packetExtensions) {
            for (PacketExtension packetExtension : packetExtensions.values()) {
                if (packetExtension.getNamespace().equals(namespace)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Remove the packet extension with the given elementName and namespace.
     *
     * @param elementName
     * @param namespace
     * @return the removed packet extension or null.
     */
    public PacketExtension removeExtension(String elementName, String namespace) {
        String key = XmppStringUtils.generateKey(elementName, namespace);
        synchronized (packetExtensions) {
            return packetExtensions.remove(key);
        }
    }

    /**
     * Removes a packet extension from the packet.
     *
     * @param extension the packet extension to remove.
     * @return the removed packet extension or null.
     */
    public PacketExtension removeExtension(PacketExtension extension)  {
        return removeExtension(extension.getElementName(), extension.getNamespace());
    }

    @Override
    // NOTE When Smack is using Java 8, then this method should be moved in Element as "Default Method".
    public String toString() {
        return toXML().toString();
    }

    /**
     * Returns the extension sub-packets (including properties data) as an XML
     * String, or the Empty String if there are no packet extensions.
     *
     * @return the extension sub-packets as XML or the Empty String if there
     * are no packet extensions.
     */
    protected final XmlStringBuilder getExtensionsXML() {
        XmlStringBuilder xml = new XmlStringBuilder();
        // Add in all standard extension sub-packets.
        for (PacketExtension extension : getExtensions()) {
            xml.append(extension.toXML());
        }
        return xml;
    }

    /**
     * Returns the default language used for all messages containing localized content.
     * 
     * @return the default language
     */
    public static String getDefaultLanguage() {
        return DEFAULT_LANGUAGE;
    }

    /**
     * Add to, from, id and 'xml:lang' attributes
     *
     * @param xml
     */
    protected void addCommonAttributes(XmlStringBuilder xml) {
        xml.optAttribute("to", getTo());
        xml.optAttribute("from", getFrom());
        xml.optAttribute("id", getStanzaId());
        xml.xmllangAttribute(getLanguage());
    }

    /**
     * Append an XMPPError is this packet has one set.
     *
     * @param xml the XmlStringBuilder to append the error to.
     */
    protected void appendErrorIfExists(XmlStringBuilder xml) {
        XMPPError error = getError();
        if (error != null) {
            xml.append(error.toXML());
        }
    }
}
