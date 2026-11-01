import java.security.*;
import java.util.Arrays;

public class HandshakeProtocolTest {

    public static void main(String[] args) throws Exception {

        // Generate ephemeral X25519 key pairs.
        KeyPair proxyEphemeral =
                KeyExchange.generateKeyPair();

        KeyPair serverEphemeral =
                KeyExchange.generateKeyPair();

        // Generate a server identity for this test.
        KeyPair serverIdentity =
                DigitalSignature.generateKeyPair();

        // 1. Proxy creates ClientHello.
        HandshakeMessage clientHello =
                HandshakeProtocol.createClientHello(
                        proxyEphemeral.getPublic(),
                        HandshakeProtocol.generateNonce()
                );

        // 2. Server validates ClientHello.
        HandshakeProtocol.ClientHello parsedClient =
                HandshakeProtocol.parseClientHello(
                        clientHello
                );

        // 3. Server creates signed ServerHello.
        HandshakeMessage serverHello =
                HandshakeProtocol.createServerHello(
                        clientHello,
                        serverEphemeral.getPublic(),
                        HandshakeProtocol.generateNonce(),
                        serverIdentity.getPrivate()
                );

        // 4. Proxy authenticates ServerHello.
        HandshakeProtocol.ServerHello parsedServer =
                HandshakeProtocol.parseServerHello(
                        clientHello,
                        serverHello,
                        serverIdentity.getPublic()
                );

        // 5. Calculate the shared secret on both sides.
        byte[] proxySecret =
                KeyExchange.calculateSharedSecret(
                        proxyEphemeral.getPrivate(),
                        KeyExchange.decodePublicKey(
                                parsedServer.publicKey()
                        )
                );

        byte[] serverSecret =
                KeyExchange.calculateSharedSecret(
                        serverEphemeral.getPrivate(),
                        KeyExchange.decodePublicKey(
                                parsedClient.publicKey()
                        )
                );

        if (!MessageDigest.isEqual(
                proxySecret, serverSecret
        )) {
            throw new AssertionError(
                    "Shared secrets do not match"
            );
        }

        // 6. Derive session keys independently.
        HandshakeProtocol.SessionKeys proxyKeys =
                HandshakeProtocol.deriveSessionKeys(
                        proxySecret,
                        clientHello,
                        serverHello
                );

        HandshakeProtocol.SessionKeys serverKeys =
                HandshakeProtocol.deriveSessionKeys(
                        serverSecret,
                        clientHello,
                        serverHello
                );

        if (!MessageDigest.isEqual(
                proxyKeys.proxyToServer(),
                serverKeys.proxyToServer()
        )) {
            throw new AssertionError(
                    "Session keys do not match"
            );
        }

        // 7. Proxy creates ClientFinished.
        HandshakeMessage finished =
                HandshakeProtocol.createClientFinished(
                        proxyKeys.proxyToServer(),
                        proxyKeys.transcriptHash()
                );

        // 8. Server verifies ClientFinished.
        boolean finishedVerified =
                HandshakeProtocol.verifyClientFinished(
                        finished,
                        serverKeys.proxyToServer(),
                        serverKeys.transcriptHash()
                );

        if (!finishedVerified) {
            throw new AssertionError(
                    "ClientFinished verification failed"
            );
        }

        System.out.println(
                "Secure handshake protocol test successful!"
        );

        System.out.println(
                "ClientHello parsed: true"
        );

        System.out.println(
                "Server identity authenticated: true"
        );

        System.out.println(
                "X25519 shared secrets match: true"
        );

        System.out.println(
                "HKDF session keys match: true"
        );

        System.out.println(
                "ClientFinished verified: true"
        );

        // Clear temporary secret arrays.
        Arrays.fill(proxySecret, (byte) 0);
        Arrays.fill(serverSecret, (byte) 0);
        Arrays.fill(
                proxyKeys.proxyToServer(), (byte) 0
        );
        Arrays.fill(
                proxyKeys.serverToProxy(), (byte) 0
        );
        Arrays.fill(
                serverKeys.proxyToServer(), (byte) 0
        );
        Arrays.fill(
                serverKeys.serverToProxy(), (byte) 0
        );
    }
}
