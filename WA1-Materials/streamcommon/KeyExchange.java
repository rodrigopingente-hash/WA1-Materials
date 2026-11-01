import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

public final class KeyExchange {

    private static final String ALGORITHM = "X25519";

    private KeyExchange() {
        // Utility class
    }

    // Generate an ephemeral X25519 key pair.
    public static KeyPair generateKeyPair()
            throws GeneralSecurityException {

        KeyPairGenerator generator =
                KeyPairGenerator.getInstance(ALGORITHM);

        return generator.generateKeyPair();
    }

    // Encode a public key for transmission.
    public static byte[] encodePublicKey(PublicKey publicKey) {

        if (publicKey == null) {
            throw new IllegalArgumentException(
                    "Public key cannot be null"
            );
        }

        if (!publicKey.getAlgorithm().equalsIgnoreCase("XDH")) {
            throw new IllegalArgumentException(
                    "Expected an X25519 public key"
            );
        }

        return publicKey.getEncoded();
    }

    // Decode a received X25519 public key.
    public static PublicKey decodePublicKey(byte[] encodedKey)
            throws GeneralSecurityException {

        if (encodedKey == null || encodedKey.length == 0) {
            throw new IllegalArgumentException(
                    "Encoded public key cannot be empty"
            );
        }

        KeyFactory factory =
                KeyFactory.getInstance(ALGORITHM);

        return factory.generatePublic(
                new X509EncodedKeySpec(encodedKey)
        );
    }

    // Calculate the shared secret.
    public static byte[] calculateSharedSecret(
            PrivateKey privateKey,
            PublicKey peerPublicKey)
            throws GeneralSecurityException {

        if (privateKey == null || peerPublicKey == null) {
            throw new IllegalArgumentException(
                    "Keys cannot be null"
            );
        }

        KeyAgreement agreement =
                KeyAgreement.getInstance(ALGORITHM);

        agreement.init(privateKey);
        agreement.doPhase(peerPublicKey, true);

        byte[] secret = agreement.generateSecret();

        if (secret.length != 32) {
            throw new GeneralSecurityException(
                    "Invalid X25519 shared secret length"
            );
        }

        // Reject an all-zero shared secret.
        int accumulator = 0;

        for (byte value : secret) {
            accumulator |= value & 0xFF;
        }

        if (accumulator == 0) {
            java.util.Arrays.fill(secret, (byte) 0);
            throw new GeneralSecurityException(
                    "Invalid all-zero X25519 shared secret"
            );
        }

        return secret;
    }
}
