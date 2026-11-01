import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

public final class SecureChannel implements AutoCloseable {

    private final Socket socket;
    private final InputStream input;
    private final OutputStream output;

    private final SecureRecord sender;
    private final SecureRecord receiver;

    private boolean closed = false;
    private boolean failed = false;

    private SecureChannel(
            Socket socket,
            HandshakeProtocol.SessionKeys keys,
            boolean isProxy)
            throws Exception {

        this.socket = socket;
        this.input = socket.getInputStream();
        this.output = socket.getOutputStream();

        if (isProxy) {
            this.sender = new SecureRecord(
                    keys.proxyToServer(),
                    keys.transcriptHash(),
                    "PROXY_TO_SERVER"
            );

            this.receiver = new SecureRecord(
                    keys.serverToProxy(),
                    keys.transcriptHash(),
                    "SERVER_TO_PROXY"
            );
        } else {
            this.sender = new SecureRecord(
                    keys.serverToProxy(),
                    keys.transcriptHash(),
                    "SERVER_TO_PROXY"
            );

            this.receiver = new SecureRecord(
                    keys.proxyToServer(),
                    keys.transcriptHash(),
                    "PROXY_TO_SERVER"
            );
        }
    }

    // Used by the Proxy.
    public static SecureChannel connect(
            Socket socket,
            PublicKey trustedServerIdentity)
            throws Exception {

        if (socket == null || socket.isClosed()) {
            throw new IllegalArgumentException(
                    "Invalid client socket"
            );
        }

        try {
            HandshakeProtocol.SessionKeys keys =
                    SecureHandshake.performClientHandshake(
                            socket,
                            trustedServerIdentity
                    );

            try {
                return new SecureChannel(
                        socket,
                        keys,
                        true
                );
            } finally {
                clearKeys(keys);
            }

        } catch (Exception e) {
            closeQuietly(socket);
            throw e;
        }
    }
    // Used by the Proxy with an external cryptographic configuration.
    public static SecureChannel connect(
            Socket socket,
            PublicKey trustedServerIdentity,
            CryptoConfig proxyConfig)
            throws Exception {

        if (socket == null || socket.isClosed()) {
            throw new IllegalArgumentException(
                    "Invalid client socket"
            );
        }

        if (proxyConfig == null) {
            throw new IllegalArgumentException(
                    "Proxy configuration is required"
            );
        }

        try {
            HandshakeProtocol.SessionKeys keys =
                    SecureHandshake.performClientHandshake(
                            socket,
                            trustedServerIdentity,
                            proxyConfig
                    );

            try {
                return new SecureChannel(
                        socket,
                        keys,
                        true
                );
            } finally {
                clearKeys(keys);
            }

        } catch (Exception e) {
            closeQuietly(socket);
            throw e;
        }
    }
    // Used by the Origin Server.
    public static SecureChannel accept(
            Socket socket,
            PrivateKey serverIdentityPrivateKey)
            throws Exception {

        if (socket == null || socket.isClosed()) {
            throw new IllegalArgumentException(
                    "Invalid server socket"
            );
        }

        try {
            HandshakeProtocol.SessionKeys keys =
                    SecureHandshake.performServerHandshake(
                            socket,
                            serverIdentityPrivateKey
                    );

            try {
                return new SecureChannel(
                        socket,
                        keys,
                        false
                );
            } finally {
                clearKeys(keys);
            }

        } catch (Exception e) {
            closeQuietly(socket);
            throw e;
        }
    }
    // Used by the Origin Server with an external configuration.
    public static SecureChannel accept(
            Socket socket,
            PrivateKey serverIdentityPrivateKey,
            CryptoConfig serverConfig)
            throws Exception {

        if (socket == null || socket.isClosed()) {
            throw new IllegalArgumentException(
                    "Invalid server socket"
            );
        }

        if (serverConfig == null) {
            throw new IllegalArgumentException(
                    "Server configuration is required"
            );
        }

        try {
            HandshakeProtocol.SessionKeys keys =
                    SecureHandshake.performServerHandshake(
                            socket,
                            serverIdentityPrivateKey,
                            serverConfig
                    );

            try {
                return new SecureChannel(
                        socket,
                        keys,
                        false
                );
            } finally {
                clearKeys(keys);
            }

        } catch (Exception e) {
            closeQuietly(socket);
            throw e;
        }
    }
    // Encrypt and send one block (maximum 1024 bytes).
    public synchronized void send(byte[] data)
            throws IOException, GeneralSecurityException {

        ensureUsable();

        try {
            sender.send(output, data);
        } catch (IOException | GeneralSecurityException
                 | RuntimeException e) {
            fail();
            throw e;
        }
    }

    // Receive and authenticate one encrypted block.
    public synchronized byte[] receive()
            throws IOException, GeneralSecurityException {

        ensureUsable();

        try {
            return receiver.receive(input);
        } catch (IOException | GeneralSecurityException
                 | RuntimeException e) {
            fail();
            throw e;
        }
    }

    public synchronized void sendText(String text)
            throws IOException, GeneralSecurityException {

        if (text == null) {
            throw new IllegalArgumentException(
                    "Text cannot be null"
            );
        }

        byte[] data = text.getBytes(
                java.nio.charset.StandardCharsets.UTF_8
        );

        if (data.length > 1024) {
            throw new IllegalArgumentException(
                    "Text exceeds maximum record size"
            );
        }

        send(data);
    }

    public synchronized String receiveText()
            throws IOException, GeneralSecurityException {

        return new String(
                receive(),
                java.nio.charset.StandardCharsets.UTF_8
        );
    }

    public synchronized boolean isOpen() {
        return !closed && !failed && !socket.isClosed();
    }

    private void ensureUsable() throws IOException {
        if (!isOpen()) {
            throw new IOException(
                    "Secure channel is closed or failed"
            );
        }
    }

    private void fail() {
        failed = true;
        closeQuietly(socket);
    }

    @Override
    public synchronized void close() {
        if (!closed) {
            closed = true;
            closeQuietly(socket);
        }
    }

    private static void clearKeys(
            HandshakeProtocol.SessionKeys keys) {

        Arrays.fill(keys.proxyToServer(), (byte) 0);
        Arrays.fill(keys.serverToProxy(), (byte) 0);
    }

    private static void closeQuietly(Socket socket) {
        try {
            socket.close();
        } catch (IOException ignored) {
        }
    }
}
