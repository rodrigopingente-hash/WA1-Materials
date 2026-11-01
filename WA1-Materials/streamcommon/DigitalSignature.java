import java.security.*;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.X509EncodedKeySpec;

public final class DigitalSignature {

    private static final String ALGORITHM = "Ed25519";
    private static final int SIGNATURE_LENGTH = 64;

    private DigitalSignature() {
        // Utility class
    }

    // Generate an Ed25519 identity key pair.
    public static KeyPair generateKeyPair()
            throws GeneralSecurityException {

        KeyPairGenerator generator =
                KeyPairGenerator.getInstance(ALGORITHM);

        return generator.generateKeyPair();
    }

    // Sign data using the private identity key.
    public static byte[] sign(
            PrivateKey privateKey,
            byte[] data)
            throws GeneralSecurityException {

        if (privateKey == null || data == null) {
            throw new IllegalArgumentException(
                    "Private key and data cannot be null"
            );
        }

        Signature signature =
                Signature.getInstance(ALGORITHM);

        signature.initSign(privateKey);
        signature.update(data);

        return signature.sign();
    }

    // Verify a digital signature.
    public static boolean verify(
            PublicKey publicKey,
            byte[] data,
            byte[] signatureBytes)
            throws GeneralSecurityException {

        if (publicKey == null
                || data == null
                || signatureBytes == null) {
            throw new IllegalArgumentException(
                    "Verification arguments cannot be null"
            );
        }

        // Ed25519 signatures must contain exactly 64 bytes.
        if (signatureBytes.length != SIGNATURE_LENGTH) {
            return false;
        }

        Signature signature =
                Signature.getInstance(ALGORITHM);

        signature.initVerify(publicKey);
        signature.update(data);

        try {
            return signature.verify(signatureBytes);

        } catch (SignatureException e) {
            // Reject malformed or invalid signatures.
            // Some Java providers throw SignatureException
            // instead of returning false.
            return false;
        }
    }

    // Encode an Ed25519 public key for storage or transmission.
    public static byte[] encodePublicKey(
            PublicKey publicKey) {

        if (!(publicKey instanceof EdECPublicKey edKey)) {
            throw new IllegalArgumentException(
                    "Expected an Ed25519 public key"
            );
        }

        // Verify the actual elliptic curve parameters.
        // Java may report the algorithm as EdDSA.
        if (!NamedParameterSpec.ED25519.getName().equals(
                edKey.getParams().getName())) {
            throw new IllegalArgumentException(
                    "Expected an Ed25519 public key"
            );
        }

        byte[] encoded = publicKey.getEncoded();

        if (encoded == null || encoded.length == 0) {
            throw new IllegalArgumentException(
                    "Public key cannot be encoded"
            );
        }

        return encoded;
    }

    // Decode an Ed25519 public key.
    public static PublicKey decodePublicKey(
            byte[] encodedKey)
            throws GeneralSecurityException {

        if (encodedKey == null
                || encodedKey.length == 0) {
            throw new IllegalArgumentException(
                    "Encoded public key cannot be empty"
            );
        }

        KeyFactory factory =
                KeyFactory.getInstance(ALGORITHM);

        PublicKey publicKey = factory.generatePublic(
                new X509EncodedKeySpec(encodedKey)
        );

        // Ensure the decoded key uses Ed25519.
        if (!(publicKey instanceof EdECPublicKey edKey)
                || !NamedParameterSpec.ED25519.getName().equals(
                edKey.getParams().getName())) {
            throw new GeneralSecurityException(
                    "Decoded key is not Ed25519"
            );
        }

        return publicKey;
    }
}
