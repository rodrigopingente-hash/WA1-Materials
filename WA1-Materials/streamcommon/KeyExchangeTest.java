import java.security.KeyPair;
import java.security.PublicKey;
import java.security.MessageDigest;
import java.util.Arrays;

public class KeyExchangeTest {

    public static void main(String[] args) throws Exception {

        // 1. Generate independent key pairs.
        KeyPair proxyKeyPair =
                KeyExchange.generateKeyPair();

        KeyPair serverKeyPair =
                KeyExchange.generateKeyPair();

        // 2. Simulate public key transmission.
        byte[] proxyPublicEncoded =
                KeyExchange.encodePublicKey(
                        proxyKeyPair.getPublic()
                );

        byte[] serverPublicEncoded =
                KeyExchange.encodePublicKey(
                        serverKeyPair.getPublic()
                );

        // 3. Decode received public keys.
        PublicKey receivedProxyPublic =
                KeyExchange.decodePublicKey(
                        proxyPublicEncoded
                );

        PublicKey receivedServerPublic =
                KeyExchange.decodePublicKey(
                        serverPublicEncoded
                );

        // 4. Calculate the shared secret on both sides.
        byte[] proxySharedSecret =
                KeyExchange.calculateSharedSecret(
                        proxyKeyPair.getPrivate(),
                        receivedServerPublic
                );

        byte[] serverSharedSecret =
                KeyExchange.calculateSharedSecret(
                        serverKeyPair.getPrivate(),
                        receivedProxyPublic
                );

        // 5. Verify both secrets match.
        if (!MessageDigest.isEqual(
                proxySharedSecret,
                serverSharedSecret
        )) {
            throw new AssertionError(
                    "X25519 shared secrets do not match"
            );
        }

        if (proxySharedSecret.length != 32) {
            throw new AssertionError(
                    "Invalid shared secret length"
            );
        }

        // 6. Test integration with HKDF.
        byte[] sessionSalt = new byte[32];
        new java.security.SecureRandom().nextBytes(sessionSalt);

        byte[] transcriptHash =
                MessageDigest.getInstance("SHA-256")
                        .digest(
                                "3S-WA1-test-handshake"
                                        .getBytes(
                                                java.nio.charset.StandardCharsets.UTF_8
                                        )
                        );

        byte[] proxyDerivedKey =
                KeyDerivation.deriveSessionKey(
                        proxySharedSecret,
                        sessionSalt,
                        transcriptHash,
                        "PROXY_TO_SERVER",
                        256
                );

        byte[] serverDerivedKey =
                KeyDerivation.deriveSessionKey(
                        serverSharedSecret,
                        sessionSalt,
                        transcriptHash,
                        "PROXY_TO_SERVER",
                        256
                );

        if (!MessageDigest.isEqual(
                proxyDerivedKey,
                serverDerivedKey
        )) {
            throw new AssertionError(
                    "HKDF-derived keys do not match"
            );
        }

        System.out.println(
                "X25519 key exchange test successful!"
        );

        System.out.println(
                "Public key encoding successful: true"
        );

        System.out.println(
                "Shared secrets match: true"
        );

        System.out.println(
                "Shared secret size: "
                        + (proxySharedSecret.length * 8)
                        + " bits"
        );

        System.out.println(
                "HKDF integration successful: true"
        );

        // Clear secret byte arrays.
        Arrays.fill(proxySharedSecret, (byte) 0);
        Arrays.fill(serverSharedSecret, (byte) 0);
        Arrays.fill(proxyDerivedKey, (byte) 0);
        Arrays.fill(serverDerivedKey, (byte) 0);
    }
}
