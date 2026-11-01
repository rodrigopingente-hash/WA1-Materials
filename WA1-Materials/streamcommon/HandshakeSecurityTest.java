import java.security.KeyPair;
import java.security.MessageDigest;
import java.util.Arrays;

public class HandshakeSecurityTest {

    public static void main(String[] args) throws Exception {

        System.out.println(
                "========================================"
        );
        System.out.println(
                "3S WA1 - Handshake Security Tests"
        );
        System.out.println(
                "========================================"
        );

        // Generate ephemeral X25519 key pairs.
        KeyPair proxyEphemeral =
                KeyExchange.generateKeyPair();

        KeyPair serverEphemeral =
                KeyExchange.generateKeyPair();

        // Generate the legitimate server identity.
        KeyPair serverIdentity =
                DigitalSignature.generateKeyPair();

        // Generate an unrelated identity for attack testing.
        KeyPair attackerIdentity =
                DigitalSignature.generateKeyPair();

        // Create the legitimate ClientHello.
        HandshakeMessage clientHello =
                HandshakeProtocol.createClientHello(
                        proxyEphemeral.getPublic(),
                        HandshakeProtocol.generateNonce()
                );

        // Create the legitimate signed ServerHello.
        HandshakeMessage serverHello =
                HandshakeProtocol.createServerHello(
                        clientHello,
                        serverEphemeral.getPublic(),
                        HandshakeProtocol.generateNonce(),
                        serverIdentity.getPrivate()
                );

        // Authenticate the legitimate ServerHello.
        HandshakeProtocol.ServerHello parsedServer =
                HandshakeProtocol.parseServerHello(
                        clientHello,
                        serverHello,
                        serverIdentity.getPublic()
                );

        // Derive the legitimate session keys.
        byte[] sharedSecret =
                KeyExchange.calculateSharedSecret(
                        proxyEphemeral.getPrivate(),
                        KeyExchange.decodePublicKey(
                                parsedServer.publicKey()
                        )
                );

        HandshakeProtocol.SessionKeys sessionKeys =
                HandshakeProtocol.deriveSessionKeys(
                        sharedSecret,
                        clientHello,
                        serverHello
                );

        // Create a legitimate ClientFinished.
        HandshakeMessage clientFinished =
                HandshakeProtocol.createClientFinished(
                        sessionKeys.proxyToServer(),
                        sessionKeys.transcriptHash()
                );

        // Verify the legitimate handshake first.
        if (!HandshakeProtocol.verifyClientFinished(
                clientFinished,
                sessionKeys.proxyToServer(),
                sessionKeys.transcriptHash()
        )) {
            throw new AssertionError(
                    "Legitimate handshake failed"
            );
        }

        System.out.println(
                "\nLegitimate handshake: PASSED"
        );

        // ========================================
        // TEST 1 - Incorrect server identity
        // ========================================

        boolean wrongIdentityRejected = false;

        try {
            HandshakeProtocol.parseServerHello(
                    clientHello,
                    serverHello,
                    attackerIdentity.getPublic()
            );
        } catch (SecurityException e) {
            wrongIdentityRejected = true;
        }

        assertRejected(
                wrongIdentityRejected,
                "Incorrect server identity"
        );

        // ========================================
        // TEST 2 - Modified ServerHello
        // ========================================

        byte[] modifiedServerPayload =
                serverHello.getPayload().clone();

        // Modify the server nonce without changing
        // the signature.
        int publicKeyLength =
                readInt(modifiedServerPayload, 0);

        int nonceOffset =
                4 + publicKeyLength + 4;

        if (nonceOffset >= modifiedServerPayload.length) {
            throw new AssertionError(
                    "Unexpected ServerHello structure"
            );
        }

        modifiedServerPayload[nonceOffset] ^= 0x01;

        HandshakeMessage modifiedServerHello =
                new HandshakeMessage(
                        HandshakeMessage.TYPE_SERVER_HELLO,
                        modifiedServerPayload
                );

        boolean modifiedServerHelloRejected = false;

        try {
            HandshakeProtocol.parseServerHello(
                    clientHello,
                    modifiedServerHello,
                    serverIdentity.getPublic()
            );
        } catch (SecurityException e) {
            modifiedServerHelloRejected = true;
        }

        assertRejected(
                modifiedServerHelloRejected,
                "Modified ServerHello"
        );

        // ========================================
        // TEST 3 - Incorrect session key
        // ========================================

        byte[] incorrectKey =
                sessionKeys.proxyToServer().clone();

        incorrectKey[0] ^= 0x01;

        boolean incorrectKeyRejected =
                !HandshakeProtocol.verifyClientFinished(
                        clientFinished,
                        incorrectKey,
                        sessionKeys.transcriptHash()
                );

        assertRejected(
                incorrectKeyRejected,
                "Incorrect session key"
        );

        // ========================================
        // TEST 4 - Modified ClientFinished
        // ========================================

        byte[] modifiedFinishedPayload =
                clientFinished.getPayload().clone();

        modifiedFinishedPayload[0] ^= 0x01;

        HandshakeMessage modifiedFinished =
                new HandshakeMessage(
                        3,
                        modifiedFinishedPayload
                );

        boolean modifiedFinishedRejected =
                !HandshakeProtocol.verifyClientFinished(
                        modifiedFinished,
                        sessionKeys.proxyToServer(),
                        sessionKeys.transcriptHash()
                );

        assertRejected(
                modifiedFinishedRejected,
                "Modified ClientFinished"
        );

        // ========================================
        // FINAL RESULTS
        // ========================================

        System.out.println(
                "\n========================================"
        );

        System.out.println(
                "All handshake security tests passed!"
        );

        System.out.println(
                "========================================"
        );

        // Clear temporary secret arrays.
        Arrays.fill(sharedSecret, (byte) 0);
        Arrays.fill(incorrectKey, (byte) 0);

        Arrays.fill(
                sessionKeys.proxyToServer(),
                (byte) 0
        );

        Arrays.fill(
                sessionKeys.serverToProxy(),
                (byte) 0
        );
    }

    // Check that an attack was rejected.
    private static void assertRejected(
            boolean rejected,
            String testName) {

        if (!rejected) {
            throw new AssertionError(
                    "Security test failed: " + testName
            );
        }

        System.out.println(
                testName + ": REJECTED"
        );
    }

    // Read a 4-byte big-endian integer.
    private static int readInt(
            byte[] data,
            int offset) {

        if (offset < 0 || offset + 4 > data.length) {
            throw new IllegalArgumentException(
                    "Invalid integer offset"
            );
        }

        return ((data[offset] & 0xFF) << 24)
                | ((data[offset + 1] & 0xFF) << 16)
                | ((data[offset + 2] & 0xFF) << 8)
                | (data[offset + 3] & 0xFF);
    }
}
