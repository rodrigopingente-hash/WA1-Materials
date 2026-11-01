import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

public final class SecureHandshake {

    private static final int MAX_MESSAGE_SIZE = 4096;

    private SecureHandshake() {
    }

    // Original API, retained for existing tests and callers.
    public static HandshakeProtocol.SessionKeys performClientHandshake(
            Socket socket,
            PublicKey trustedServerIdentity) throws Exception {
        return performClientHandshakeInternal(socket, trustedServerIdentity, null);
    }

    // Configurable API: uses the Proxy XML configuration for ClientHello.
    public static HandshakeProtocol.SessionKeys performClientHandshake(
            Socket socket,
            PublicKey trustedServerIdentity,
            CryptoConfig proxyConfig) throws Exception {
        validateRecordConfiguration(proxyConfig);
        return performClientHandshakeInternal(socket, trustedServerIdentity, proxyConfig);
    }

    private static HandshakeProtocol.SessionKeys performClientHandshakeInternal(
            Socket socket,
            PublicKey trustedServerIdentity,
            CryptoConfig proxyConfig) throws Exception {

        if (socket == null || trustedServerIdentity == null) {
            throw new IllegalArgumentException("Socket and trusted identity are required");
        }

        InputStream in = socket.getInputStream();
        OutputStream out = socket.getOutputStream();
        KeyPair proxyEphemeral = KeyExchange.generateKeyPair();

        HandshakeMessage clientHello = proxyConfig == null
                ? HandshakeProtocol.createClientHello(
                proxyEphemeral.getPublic(), HandshakeProtocol.generateNonce())
                : HandshakeProtocol.createClientHello(
                proxyEphemeral.getPublic(), HandshakeProtocol.generateNonce(), proxyConfig);
        sendMessage(out, clientHello);

        HandshakeMessage serverHello = receiveMessage(in);
        HandshakeProtocol.ServerHello parsedServer = HandshakeProtocol.parseServerHello(
                clientHello, serverHello, trustedServerIdentity);

        // The selected suite must match the Proxy's proposal.
        HandshakeProtocol.ClientHello parsedClient = HandshakeProtocol.parseClientHello(clientHello);
        if (!parsedClient.cipherSuite().equals(parsedServer.cipherSuite())) {
            throw new SecurityException("Server selected a different cipher suite");
        }

        byte[] sharedSecret = KeyExchange.calculateSharedSecret(
                proxyEphemeral.getPrivate(),
                KeyExchange.decodePublicKey(parsedServer.publicKey()));

        HandshakeProtocol.SessionKeys keys = null;
        boolean success = false;
        try {
            keys = HandshakeProtocol.deriveSessionKeys(sharedSecret, clientHello, serverHello);
            HandshakeMessage finished = HandshakeProtocol.createClientFinished(
                    keys.proxyToServer(), keys.transcriptHash());
            sendMessage(out, finished);
            success = true;
            return keys;
        } finally {
            Arrays.fill(sharedSecret, (byte) 0);
            if (!success && keys != null) {
                clearSessionKeys(keys);
            }
        }
    }

    // Original API, retained for existing tests and callers.
    public static HandshakeProtocol.SessionKeys performServerHandshake(
            Socket socket,
            PrivateKey serverIdentityPrivateKey) throws Exception {
        return performServerHandshakeInternal(socket, serverIdentityPrivateKey, null);
    }

    // Configurable API: checks ClientHello against the Server XML configuration.
    public static HandshakeProtocol.SessionKeys performServerHandshake(
            Socket socket,
            PrivateKey serverIdentityPrivateKey,
            CryptoConfig serverConfig) throws Exception {
        validateRecordConfiguration(serverConfig);
        return performServerHandshakeInternal(socket, serverIdentityPrivateKey, serverConfig);
    }

    private static HandshakeProtocol.SessionKeys performServerHandshakeInternal(
            Socket socket,
            PrivateKey serverIdentityPrivateKey,
            CryptoConfig serverConfig) throws Exception {

        if (socket == null || serverIdentityPrivateKey == null) {
            throw new IllegalArgumentException("Socket and server identity are required");
        }

        InputStream in = socket.getInputStream();
        OutputStream out = socket.getOutputStream();

        HandshakeMessage clientHello = receiveMessage(in);
        HandshakeProtocol.ClientHello parsedClient = serverConfig == null
                ? HandshakeProtocol.parseClientHello(clientHello)
                : HandshakeProtocol.parseClientHello(clientHello, serverConfig);

        KeyPair serverEphemeral = KeyExchange.generateKeyPair();
        HandshakeMessage serverHello = HandshakeProtocol.createServerHello(
                clientHello,
                serverEphemeral.getPublic(),
                HandshakeProtocol.generateNonce(),
                serverIdentityPrivateKey);
        sendMessage(out, serverHello);

        byte[] sharedSecret = KeyExchange.calculateSharedSecret(
                serverEphemeral.getPrivate(),
                KeyExchange.decodePublicKey(parsedClient.publicKey()));

        HandshakeProtocol.SessionKeys keys = null;
        boolean success = false;
        try {
            keys = HandshakeProtocol.deriveSessionKeys(sharedSecret, clientHello, serverHello);
            HandshakeMessage finished = receiveMessage(in);
            boolean verified = HandshakeProtocol.verifyClientFinished(
                    finished, keys.proxyToServer(), keys.transcriptHash());
            if (!verified) {
                throw new SecurityException("ClientFinished verification failed");
            }
            success = true;
            return keys;
        } finally {
            Arrays.fill(sharedSecret, (byte) 0);
            if (!success && keys != null) {
                clearSessionKeys(keys);
            }
        }
    }

    private static void validateRecordConfiguration(CryptoConfig config) throws Exception {
        if (config == null) {
            throw new IllegalArgumentException("Cryptographic configuration is required");
        }
        config.validate();
        if (!"AES/GCM/NULL/NULL".equals(config.getCipherSuiteIdentifier())
                || (config.getKeySize() != 128 && config.getKeySize() != 192 && config.getKeySize() != 256)
                || config.getIvSize() != 96) {
            throw new IllegalArgumentException(
                    "SecureRecord supports AES-128/192/256-GCM with a 96-bit IV");
        }
    }

    private static void sendMessage(OutputStream out, HandshakeMessage message)
            throws IOException {
        if (message == null || message.getPayloadLength() >
                MAX_MESSAGE_SIZE - HandshakeMessage.HEADER_SIZE) {
            throw new IOException("Invalid handshake message size");
        }
        message.writeTo(out);
    }

    private static HandshakeMessage receiveMessage(InputStream in) throws IOException {
        HandshakeMessage message = HandshakeMessage.readFrom(in);
        if (message.getPayloadLength() >
                MAX_MESSAGE_SIZE - HandshakeMessage.HEADER_SIZE) {
            throw new IOException("Invalid handshake message size");
        }
        return message;
    }

    private static void clearSessionKeys(HandshakeProtocol.SessionKeys keys) {
        Arrays.fill(keys.proxyToServer(), (byte) 0);
        Arrays.fill(keys.serverToProxy(), (byte) 0);
        Arrays.fill(keys.transcriptHash(), (byte) 0);
    }
}
