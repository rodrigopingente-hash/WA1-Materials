import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;

public final class HandshakeProtocol {

    private static final String CIPHER_SUITE =
            "AES/GCM/NULL/NULL";

    private static final int NONCE_LENGTH = 32;
    private static final int MAX_KEY_LENGTH = 256;

    // Handshake message types
    private static final int TYPE_CLIENT_FINISHED = 3;

    private static final SecureRandom RANDOM =
            new SecureRandom();

    private HandshakeProtocol() {
        // Utility class
    }

    public record ClientHello(
            byte[] nonce,
            byte[] publicKey,
            String cipherSuite) {
    }

    public record ServerHello(
            byte[] nonce,
            byte[] publicKey,
            String cipherSuite,
            byte[] signature) {
    }

    public record SessionKeys(
            byte[] proxyToServer,
            byte[] serverToProxy,
            byte[] transcriptHash) {
    }

    // Create a ClientHello message.
    // Create ClientHello using an external cryptographic configuration.
    public static HandshakeMessage createClientHello(
            PublicKey proxyPublicKey,
            byte[] proxyNonce,
            CryptoConfig config) throws Exception {

        if (config == null) {
            throw new IllegalArgumentException(
                    "Cryptographic configuration is required"
            );
        }

        config.validate();

        ByteArrayOutputStream buffer =
                new ByteArrayOutputStream();

        DataOutputStream output =
                new DataOutputStream(buffer);

        validateNonce(proxyNonce);

        writeBytes(
                output,
                KeyExchange.encodePublicKey(proxyPublicKey)
        );

        writeBytes(output, proxyNonce);

        output.writeUTF(config.getNegotiationIdentifier());
        output.flush();

        return new HandshakeMessage(
                HandshakeMessage.TYPE_CLIENT_HELLO,
                buffer.toByteArray()
        );
    }
    public static HandshakeMessage createClientHello(
            PublicKey proxyPublicKey,
            byte[] proxyNonce) throws Exception {

        validateNonce(proxyNonce);

        ByteArrayOutputStream buffer =
                new ByteArrayOutputStream();

        DataOutputStream output =
                new DataOutputStream(buffer);

        writeBytes(
                output,
                KeyExchange.encodePublicKey(proxyPublicKey)
        );

        writeBytes(output, proxyNonce);
        output.writeUTF(CIPHER_SUITE);
        output.flush();

        return new HandshakeMessage(
                HandshakeMessage.TYPE_CLIENT_HELLO,
                buffer.toByteArray()
        );
    }

    // Parse and validate ClientHello.
    // Parse ClientHello and validate it against the server configuration.
    public static ClientHello parseClientHello(
            HandshakeMessage message,
            CryptoConfig serverConfig) throws Exception {

        if (serverConfig == null) {
            throw new IllegalArgumentException(
                    "Server cryptographic configuration is required"
            );
        }

        serverConfig.validate();

        ClientHello clientHello = parseClientHello(message);

        String proposedSuite = clientHello.cipherSuite();
        String supportedSuite = serverConfig.getNegotiationIdentifier();

        if (!proposedSuite.equalsIgnoreCase(supportedSuite)) {
            throw new SecurityException(
                    "Incompatible cryptographic configuration. "
                            + "Proxy proposed: " + proposedSuite
                            + ", Server supports: " + supportedSuite
            );
        }

        return clientHello;
    }
    public static ClientHello parseClientHello(
            HandshakeMessage message) throws Exception {

        requireType(
                message,
                HandshakeMessage.TYPE_CLIENT_HELLO
        );

        DataInputStream input =
                new DataInputStream(
                        new ByteArrayInputStream(
                                message.getPayload()
                        )
                );

        byte[] publicKey = readBytes(input);
        byte[] nonce = readBytes(input);
        String suite = input.readUTF();

        validateNonce(nonce);
        validateCipherSuite(suite);
        KeyExchange.decodePublicKey(publicKey);
        requireEnd(input);

        return new ClientHello(
                nonce,
                publicKey,
                suite
        );
    }

    // Create a signed ServerHello.
    public static HandshakeMessage createServerHello(
            HandshakeMessage clientHello,
            PublicKey serverEphemeralPublicKey,
            byte[] serverNonce,
            PrivateKey identityPrivateKey) throws Exception {

        parseClientHello(clientHello);
        validateNonce(serverNonce);

        ByteArrayOutputStream buffer =
                new ByteArrayOutputStream();

        DataOutputStream output =
                new DataOutputStream(buffer);

        writeBytes(
                output,
                KeyExchange.encodePublicKey(
                        serverEphemeralPublicKey
                )
        );

        writeBytes(output, serverNonce);
        output.writeUTF(parseClientHello(clientHello).cipherSuite());
        output.flush();

        byte[] unsignedPayload = buffer.toByteArray();

        byte[] signedData = concat(
                clientHello.getPayload(),
                unsignedPayload
        );

        byte[] signature =
                DigitalSignature.sign(
                        identityPrivateKey,
                        signedData
                );

        writeBytes(output, signature);
        output.flush();

        return new HandshakeMessage(
                HandshakeMessage.TYPE_SERVER_HELLO,
                buffer.toByteArray()
        );
    }

    // Parse and authenticate ServerHello.
    public static ServerHello parseServerHello(
            HandshakeMessage clientHello,
            HandshakeMessage serverHello,
            PublicKey trustedIdentityPublicKey)
            throws Exception {

        parseClientHello(clientHello);

        requireType(
                serverHello,
                HandshakeMessage.TYPE_SERVER_HELLO
        );

        DataInputStream input =
                new DataInputStream(
                        new ByteArrayInputStream(
                                serverHello.getPayload()
                        )
                );

        byte[] publicKey = readBytes(input);
        byte[] nonce = readBytes(input);
        String suite = input.readUTF();
        byte[] signature = readBytes(input);

        validateNonce(nonce);
        validateCipherSuite(suite);
        KeyExchange.decodePublicKey(publicKey);
        requireEnd(input);

        ByteArrayOutputStream unsignedBuffer =
                new ByteArrayOutputStream();

        DataOutputStream unsignedOutput =
                new DataOutputStream(unsignedBuffer);

        writeBytes(unsignedOutput, publicKey);
        writeBytes(unsignedOutput, nonce);
        unsignedOutput.writeUTF(suite);
        unsignedOutput.flush();

        byte[] signedData = concat(
                clientHello.getPayload(),
                unsignedBuffer.toByteArray()
        );

        if (!DigitalSignature.verify(
                trustedIdentityPublicKey,
                signedData,
                signature
        )) {
            throw new SecurityException(
                    "Server identity authentication failed"
            );
        }

        return new ServerHello(
                nonce,
                publicKey,
                suite,
                signature
        );
    }

    // Derive session keys from the handshake.
    public static SessionKeys deriveSessionKeys(
            byte[] sharedSecret,
            HandshakeMessage clientHello,
            HandshakeMessage serverHello)
            throws Exception {

        ClientHello client =
                parseClientHello(clientHello);

        requireType(
                serverHello,
                HandshakeMessage.TYPE_SERVER_HELLO
        );

        byte[] salt =
                MessageDigest.getInstance("SHA-256")
                        .digest(
                                concat(
                                        client.nonce(),
                                        extractServerNonce(
                                                serverHello
                                        )
                                )
                        );

        byte[] transcriptHash =
                MessageDigest.getInstance("SHA-256")
                        .digest(
                                concat(
                                        clientHello.getPayload(),
                                        serverHello.getPayload()
                                )
                        );

        byte[] proxyKey =
                KeyDerivation.deriveSessionKey(
                        sharedSecret,
                        salt,
                        transcriptHash,
                        "PROXY_TO_SERVER",
                        keySizeFromSuite(client.cipherSuite())
                );

        byte[] serverKey =
                KeyDerivation.deriveSessionKey(
                        sharedSecret,
                        salt,
                        transcriptHash,
                        "SERVER_TO_PROXY",
                        keySizeFromSuite(client.cipherSuite())
                );

        return new SessionKeys(
                proxyKey,
                serverKey,
                transcriptHash
        );
    }

    // Create ClientFinished confirmation.
    public static HandshakeMessage createClientFinished(
            byte[] proxyToServerKey,
            byte[] transcriptHash) throws Exception {

        byte[] confirmation =
                calculateConfirmation(
                        proxyToServerKey,
                        transcriptHash
                );

        return new HandshakeMessage(
                TYPE_CLIENT_FINISHED,
                confirmation
        );
    }

    // Verify ClientFinished confirmation.
    public static boolean verifyClientFinished(
            HandshakeMessage message,
            byte[] proxyToServerKey,
            byte[] transcriptHash) throws Exception {

        requireType(
                message,
                TYPE_CLIENT_FINISHED
        );

        byte[] expected =
                calculateConfirmation(
                        proxyToServerKey,
                        transcriptHash
                );

        return MessageDigest.isEqual(
                expected,
                message.getPayload()
        );
    }

    // Generate a cryptographically secure nonce.
    public static byte[] generateNonce() {

        byte[] nonce = new byte[NONCE_LENGTH];
        RANDOM.nextBytes(nonce);

        return nonce;
    }

    // Calculate HMAC-based handshake confirmation.
    private static byte[] calculateConfirmation(
            byte[] key,
            byte[] transcriptHash) throws Exception {

        Mac mac = Mac.getInstance("HmacSHA256");

        mac.init(
                new SecretKeySpec(
                        key,
                        "HmacSHA256"
                )
        );

        mac.update(
                "3S-WA1-ClientFinished"
                        .getBytes(StandardCharsets.UTF_8)
        );

        mac.update(transcriptHash);

        return mac.doFinal();
    }

    // Extract the ServerHello nonce.
    private static byte[] extractServerNonce(
            HandshakeMessage message) throws Exception {

        DataInputStream input =
                new DataInputStream(
                        new ByteArrayInputStream(
                                message.getPayload()
                        )
                );

        readBytes(input);

        byte[] nonce = readBytes(input);

        validateNonce(nonce);

        return nonce;
    }

    // Write a length-prefixed byte array.
    private static void writeBytes(
            DataOutputStream output,
            byte[] bytes) throws IOException {

        output.writeInt(bytes.length);
        output.write(bytes);
    }

    // Read a length-prefixed byte array.
    private static byte[] readBytes(
            DataInputStream input) throws IOException {

        int length = input.readInt();

        if (length < 1 || length > MAX_KEY_LENGTH) {
            throw new IOException(
                    "Invalid handshake field length"
            );
        }

        byte[] bytes = new byte[length];

        input.readFully(bytes);

        return bytes;
    }

    // Validate a handshake nonce.
    private static void validateNonce(byte[] nonce) {

        if (nonce == null
                || nonce.length != NONCE_LENGTH) {
            throw new IllegalArgumentException(
                    "Nonce must contain 32 bytes"
            );
        }
    }

    // Legacy handshake uses AES-256; configurable handshakes bind key/IV size.
    private static int keySizeFromSuite(String suite) {
        validateCipherSuite(suite);
        if (CIPHER_SUITE.equals(suite)) return 256;
        String key = suite.substring((CIPHER_SUITE + ";KEYSIZE=").length(),
                suite.indexOf(";IVSIZE="));
        return Integer.parseInt(key);
    }

    private static void validateCipherSuite(String suite) {
        if (CIPHER_SUITE.equals(suite)) return;
        if (suite == null || !suite.matches(
                "AES/GCM/NULL/NULL;KEYSIZE=(128|192|256);IVSIZE=96")) {
            throw new SecurityException("Unsupported cipher suite: " + suite);
        }
    }

    // Validate the handshake message type.
    private static void requireType(
            HandshakeMessage message,
            int expectedType) {

        if (message == null
                || message.getType() != expectedType) {
            throw new IllegalArgumentException(
                    "Unexpected handshake message type"
            );
        }
    }

    // Reject unexpected trailing data.
    private static void requireEnd(
            DataInputStream input) throws IOException {

        if (input.available() != 0) {
            throw new IOException(
                    "Unexpected trailing handshake data"
            );
        }
    }

    // Concatenate two byte arrays.
    private static byte[] concat(
            byte[] first,
            byte[] second) {

        byte[] result =
                Arrays.copyOf(
                        first,
                        first.length + second.length
                );

        System.arraycopy(
                second,
                0,
                result,
                first.length,
                second.length
        );

        return result;
    }
}
