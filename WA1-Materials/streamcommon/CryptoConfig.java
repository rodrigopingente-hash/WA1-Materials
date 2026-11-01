import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.File;
import java.util.Set;

public class CryptoConfig {

    private final String algorithm;
    private final String mode;
    private final String iv;
    private final int ivSize;
    private final String padding;
    private final String macAlgorithm;
    private final String symmetricKey;
    private final int keySize;
    private final String macKey;
    private final String macKeySize;

    private CryptoConfig(
            String algorithm,
            String mode,
            String iv,
            int ivSize,
            String padding,
            String macAlgorithm,
            String symmetricKey,
            int keySize,
            String macKey,
            String macKeySize) {

        this.algorithm = algorithm;
        this.mode = mode;
        this.iv = iv;
        this.ivSize = ivSize;
        this.padding = padding;
        this.macAlgorithm = macAlgorithm;
        this.symmetricKey = symmetricKey;
        this.keySize = keySize;
        this.macKey = macKey;
        this.macKeySize = macKeySize;
    }

    // Reads the cryptographic configuration from XML.
    public static CryptoConfig load(String filePath)
            throws Exception {

        DocumentBuilderFactory factory =
                DocumentBuilderFactory.newInstance();

        // Prevent XML external entity attacks.
        factory.setFeature(
                "http://apache.org/xml/features/disallow-doctype-decl",
                true
        );

        factory.setFeature(
                "http://xml.org/sax/features/external-general-entities",
                false
        );

        factory.setFeature(
                "http://xml.org/sax/features/external-parameter-entities",
                false
        );

        factory.setFeature(
                XMLConstants.FEATURE_SECURE_PROCESSING,
                true
        );

        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        factory.setAttribute(
                XMLConstants.ACCESS_EXTERNAL_DTD, ""
        );
        factory.setAttribute(
                XMLConstants.ACCESS_EXTERNAL_SCHEMA, ""
        );

        DocumentBuilder builder =
                factory.newDocumentBuilder();

        Document document =
                builder.parse(new File(filePath));

        document.getDocumentElement().normalize();

        Element root = document.getDocumentElement();

        String rootName = root.getTagName();

        if (!rootName.equals("ProxyCryptoConfig")
                && !rootName.equals("ServerCryptoConfig")) {

            throw new IllegalArgumentException(
                    "Invalid root element: " + rootName
            );
        }

        Element cipherSuite =
                getChild(root, "SymCipherSuite");

        Element ivElement =
                getChild(cipherSuite, "InitializationVector");

        Element macSuite =
                getChild(root, "MACSuite");

        Element configuredKeys =
                getChild(root, "ConfiguredKeys");

        Element symmetricKeyElement =
                getChild(configuredKeys, "SymmetricKey");

        Element macKeyElement =
                getChild(configuredKeys, "MACKey");

        CryptoConfig config = new CryptoConfig(
                getText(cipherSuite, "Algorithm"),
                getText(cipherSuite, "Mode"),
                getText(ivElement, "IV"),
                Integer.parseInt(getText(ivElement, "IVSize")),
                getText(cipherSuite, "Padding"),
                getText(macSuite, "Algorithm"),
                getText(symmetricKeyElement, "SKey"),
                Integer.parseInt(
                        getText(symmetricKeyElement, "KeySize")
                ),
                getText(macKeyElement, "MacKey"),
                getText(macKeyElement, "MacKeySize")
        );

        config.validate();
        return config;
    }

    private static Element getChild(
            Element parent, String name) {

        NodeList children = parent.getChildNodes();

        for (int i = 0; i < children.getLength(); i++) {
            Node node = children.item(i);

            if (node instanceof Element element
                    && element.getTagName().equals(name)) {
                return element;
            }
        }

        throw new IllegalArgumentException(
                "Missing XML element: " + name
        );
    }

    private static String getText(
            Element parent, String name) {

        String value =
                getChild(parent, name).getTextContent().trim();

        if (value.isEmpty()) {
            throw new IllegalArgumentException(
                    "Empty XML element: " + name
            );
        }

        return value;
    }

    // Validate only configurations currently implemented.
    public void validate() {

        if (!algorithm.equalsIgnoreCase("AES")
                || !mode.equalsIgnoreCase("GCM")) {

            throw new IllegalArgumentException(
                    "Unsupported cipher suite: "
                            + algorithm + "/" + mode
            );
        }

        if (!Set.of(128, 192, 256).contains(keySize)) {
            throw new IllegalArgumentException(
                    "Invalid AES key size: " + keySize
            );
        }

        if (ivSize != 96) {
            throw new IllegalArgumentException(
                    "AES-GCM requires a 96-bit IV "
                            + "in this implementation"
            );
        }

        if (!iv.equalsIgnoreCase("NULL")) {
            throw new IllegalArgumentException(
                    "Static IV values are not supported"
            );
        }

        if (!padding.equalsIgnoreCase("NULL")) {
            throw new IllegalArgumentException(
                    "AES-GCM must not use padding"
            );
        }

        if (!macAlgorithm.equalsIgnoreCase("NULL")) {
            throw new IllegalArgumentException(
                    "AES-GCM uses its own authentication tag"
            );
        }

        if (!symmetricKey.equalsIgnoreCase("NULL")) {
            throw new IllegalArgumentException(
                    "Session keys must be derived dynamically"
            );
        }

        if (!macKey.equalsIgnoreCase("NULL")
                || !macKeySize.equalsIgnoreCase("NULL")) {

            throw new IllegalArgumentException(
                    "Separate MAC keys are not used with AES-GCM"
            );
        }
    }

    // Negotiation identifier sent during the handshake.
    public String getCipherSuiteIdentifier() {
        return algorithm + "/" + mode + "/"
                + iv + "/" + padding;
    }

    public String getNegotiationIdentifier() {
        return getCipherSuiteIdentifier() + ";KEYSIZE=" + keySize + ";IVSIZE=" + ivSize;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public String getMode() {
        return mode;
    }

    public String getIv() {
        return iv;
    }

    public int getIvSize() {
        return ivSize;
    }

    public String getPadding() {
        return padding;
    }

    public String getMacAlgorithm() {
        return macAlgorithm;
    }

    public int getKeySize() {
        return keySize;
    }

    public String getSymmetricKey() {
        return symmetricKey;
    }

    public String getMacKey() {
        return macKey;
    }

    public String getMacKeySize() {
        return macKeySize;
    }

    @Override
    public String toString() {
        return "CryptoConfig{" +
                "algorithm='" + algorithm + '\'' +
                ", mode='" + mode + '\'' +
                ", ivSize=" + ivSize +
                ", keySize=" + keySize +
                ", macAlgorithm='" + macAlgorithm + '\'' +
                '}';
    }
}
