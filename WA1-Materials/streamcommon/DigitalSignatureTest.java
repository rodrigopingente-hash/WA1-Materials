import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;

public class DigitalSignatureTest {

    public static void main(String[] args) throws Exception {

        // 1. Generate server identity keys.
        KeyPair serverIdentity =
                DigitalSignature.generateKeyPair();

        // 2. Simulate handshake data.
        byte[] handshakeData =
                "3S-WA1-handshake-X25519-public-keys"
                        .getBytes(StandardCharsets.UTF_8);

        // 3. Sign the handshake data.
        byte[] signature =
                DigitalSignature.sign(
                        serverIdentity.getPrivate(),
                        handshakeData
                );

        // 4. Encode and decode the public key.
        byte[] encodedPublicKey =
                DigitalSignature.encodePublicKey(
                        serverIdentity.getPublic()
                );

        PublicKey receivedPublicKey =
                DigitalSignature.decodePublicKey(
                        encodedPublicKey
                );

        // 5. Verify a valid signature.
        boolean validSignature =
                DigitalSignature.verify(
                        receivedPublicKey,
                        handshakeData,
                        signature
                );

        if (!validSignature) {
            throw new AssertionError(
                    "Valid signature was rejected"
            );
        }

        // 6. Verify that modified data is rejected.
        byte[] modifiedData = handshakeData.clone();
        modifiedData[0] ^= 0x01;

        boolean modifiedDataAccepted =
                DigitalSignature.verify(
                        receivedPublicKey,
                        modifiedData,
                        signature
                );

        if (modifiedDataAccepted) {
            throw new AssertionError(
                    "Modified data was accepted"
            );
        }

        // 7. Verify that a modified signature is rejected.
        byte[] modifiedSignature = signature.clone();
        modifiedSignature[0] ^= 0x01;

        boolean modifiedSignatureAccepted =
                DigitalSignature.verify(
                        receivedPublicKey,
                        handshakeData,
                        modifiedSignature
                );

        if (modifiedSignatureAccepted) {
            throw new AssertionError(
                    "Modified signature was accepted"
            );
        }

        // 8. Verify that a different identity is rejected.
        KeyPair attackerIdentity =
                DigitalSignature.generateKeyPair();

        boolean wrongIdentityAccepted =
                DigitalSignature.verify(
                        attackerIdentity.getPublic(),
                        handshakeData,
                        signature
                );

        if (wrongIdentityAccepted) {
            throw new AssertionError(
                    "Wrong identity was accepted"
            );
        }

        System.out.println(
                "Ed25519 digital signature test successful!"
        );

        System.out.println(
                "Valid signature accepted: "
                        + validSignature
        );

        System.out.println(
                "Modified data rejected: "
                        + !modifiedDataAccepted
        );

        System.out.println(
                "Modified signature rejected: "
                        + !modifiedSignatureAccepted
        );

        System.out.println(
                "Wrong identity rejected: "
                        + !wrongIdentityAccepted
        );

        System.out.println(
                "Signature size: "
                        + (signature.length * 8)
                        + " bits"
        );

        Arrays.fill(signature, (byte) 0);
        Arrays.fill(modifiedSignature, (byte) 0);
    }
}
