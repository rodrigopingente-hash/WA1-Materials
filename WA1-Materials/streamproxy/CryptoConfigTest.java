public class CryptoConfigTest {

    public static void main(String[] args) {
        try {
            CryptoConfig proxyConfig = CryptoConfig.load(
                    "streamproxy/proxycrypto.config"
            );

            CryptoConfig serverConfig = CryptoConfig.load(
                    "streamserver/sservercrypto.config"
            );
            System.out.println("\nCrypto configuration test successful!");
            System.out.println("========================================");
            System.out.println("3S WA1 - Crypto Configuration Test");
            System.out.println("========================================");

            System.out.println("\nProxy configuration: "
                    + proxyConfig.getCipherSuiteIdentifier());

            System.out.println("Server configuration: "
                    + serverConfig.getCipherSuiteIdentifier());

            if (!proxyConfig.getCipherSuiteIdentifier().equalsIgnoreCase(
                    serverConfig.getCipherSuiteIdentifier())) {

                throw new IllegalStateException(
                        "Proxy and Server configurations are incompatible"
                );
            }

            if (proxyConfig.getKeySize() != serverConfig.getKeySize()
                    || proxyConfig.getIvSize() != serverConfig.getIvSize()) {

                throw new IllegalStateException(
                        "Proxy and Server key/IV sizes are incompatible"
                );
            }

            System.out.println("\nBoth XML files loaded: PASSED");
            System.out.println("Cryptographic compatibility: PASSED");
            System.out.println("\nCrypto configuration test successful!");
// Test cryptographic configuration negotiation.
            java.security.KeyPair proxyKeyPair =
                    KeyExchange.generateKeyPair();

            byte[] proxyNonce = HandshakeProtocol.generateNonce();

            HandshakeMessage clientHello =
                    HandshakeProtocol.createClientHello(
                            proxyKeyPair.getPublic(),
                            proxyNonce,
                            proxyConfig
                    );

            HandshakeProtocol.ClientHello parsedHello =
                    HandshakeProtocol.parseClientHello(
                            clientHello,
                            serverConfig
                    );

            if (!parsedHello.cipherSuite().equalsIgnoreCase(
                    proxyConfig.getCipherSuiteIdentifier())) {

                throw new IllegalStateException(
                        "Negotiated cipher suite does not match the Proxy configuration"
                );
            }

            System.out.println("ClientHello negotiation: PASSED");
            System.out.println("Server configuration validation: PASSED");
        } catch (Exception e) {
            System.err.println("Crypto configuration test FAILED!");
            e.printStackTrace();
            System.exit(1);
        }
    }
}