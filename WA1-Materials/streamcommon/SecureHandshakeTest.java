import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.concurrent.*;

public class SecureHandshakeTest {

    public static void main(String[] args) throws Exception {

        System.out.println(
                "========================================"
        );
        System.out.println(
                "3S WA1 - Secure TCP Handshake Test"
        );
        System.out.println(
                "========================================"
        );

        KeyPair serverIdentity =
                DigitalSignature.generateKeyPair();

        ExecutorService executor =
                Executors.newSingleThreadExecutor();

        try (ServerSocket listener = new ServerSocket(0)) {

            int port = listener.getLocalPort();

            listener.setSoTimeout(5000);

            // Start the server side in another thread.
            Future<HandshakeProtocol.SessionKeys> serverFuture =
                    executor.submit(() -> {

                        try (Socket serverSocket =
                                     listener.accept()) {

                            serverSocket.setSoTimeout(5000);

                            return SecureHandshake
                                    .performServerHandshake(
                                            serverSocket,
                                            serverIdentity.getPrivate()
                                    );
                        }
                    });

            // Connect the simulated Proxy.
            HandshakeProtocol.SessionKeys clientKeys;

            try (Socket clientSocket =
                         new Socket("localhost", port)) {

                clientSocket.setSoTimeout(5000);

                clientKeys =
                        SecureHandshake.performClientHandshake(
                                clientSocket,
                                serverIdentity.getPublic()
                        );
            }

            // Wait for the server handshake to finish.
            HandshakeProtocol.SessionKeys serverKeys =
                    serverFuture.get(
                            5,
                            TimeUnit.SECONDS
                    );

            // Compare Proxy -> Server keys.
            boolean proxyKeysMatch =
                    MessageDigest.isEqual(
                            clientKeys.proxyToServer(),
                            serverKeys.proxyToServer()
                    );

            // Compare Server -> Proxy keys.
            boolean serverKeysMatch =
                    MessageDigest.isEqual(
                            clientKeys.serverToProxy(),
                            serverKeys.serverToProxy()
                    );

            // Confirm directional key separation.
            boolean directionsSeparated =
                    !MessageDigest.isEqual(
                            clientKeys.proxyToServer(),
                            clientKeys.serverToProxy()
                    );

            // Compare transcript hashes.
            boolean transcriptMatches =
                    MessageDigest.isEqual(
                            clientKeys.transcriptHash(),
                            serverKeys.transcriptHash()
                    );

            if (!proxyKeysMatch
                    || !serverKeysMatch
                    || !directionsSeparated
                    || !transcriptMatches) {

                throw new AssertionError(
                        "Secure TCP handshake validation failed"
                );
            }

            System.out.println(
                    "\nTCP connection established: true"
            );

            System.out.println(
                    "Server identity authenticated: true"
            );

            System.out.println(
                    "ClientFinished verified: true"
            );

            System.out.println(
                    "Proxy-to-Server keys match: true"
            );

            System.out.println(
                    "Server-to-Proxy keys match: true"
            );

            System.out.println(
                    "Directional keys separated: true"
            );

            System.out.println(
                    "Handshake transcript matches: true"
            );

            System.out.println(
                    "\nSecure TCP handshake test successful!"
            );

            // Clear temporary session key arrays.
            Arrays.fill(
                    clientKeys.proxyToServer(), (byte) 0
            );

            Arrays.fill(
                    clientKeys.serverToProxy(), (byte) 0
            );

            Arrays.fill(
                    serverKeys.proxyToServer(), (byte) 0
            );

            Arrays.fill(
                    serverKeys.serverToProxy(), (byte) 0
            );

        } finally {
            executor.shutdownNow();
        }
    }
}
