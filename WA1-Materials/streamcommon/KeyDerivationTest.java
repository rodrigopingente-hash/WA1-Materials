import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;

public class KeyDerivationTest {

    public static void main(String[] args) throws Exception {

        // Synthetic test secret.
        // Real secrets will come from X25519.
        byte[] sharedSecret =
                "test-shared-secret-3S-WA1"
                        .getBytes(StandardCharsets.UTF_8);

        byte[] salt =
                "test-session-salt"
                        .getBytes(StandardCharsets.UTF_8);

        byte[] transcriptHash =
                MessageDigest.getInstance("SHA-256")
                        .digest(
                                "test-handshake-transcript"
                                        .getBytes(
                                                StandardCharsets.UTF_8
                                        )
                        );

        byte[] proxyKey =
                KeyDerivation.deriveSessionKey(
                        sharedSecret,
                        salt,
                        transcriptHash,
                        "PROXY_TO_SERVER",
                        256
                );

        byte[] serverKey =
                KeyDerivation.deriveSessionKey(
                        sharedSecret,
                        salt,
                        transcriptHash,
                        "SERVER_TO_PROXY",
                        256
                );

        byte[] proxyKeyRepeated =
                KeyDerivation.deriveSessionKey(
                        sharedSecret,
                        salt,
                        transcriptHash,
                        "PROXY_TO_SERVER",
                        256
                );

        if (proxyKey.length != 32 || serverKey.length != 32) {
            throw new AssertionError(
                    "Invalid AES-256 key length"
            );
        }

        if (Arrays.equals(proxyKey, serverKey)) {
            throw new AssertionError(
                    "Directional keys must be different"
            );
        }

        if (!Arrays.equals(proxyKey, proxyKeyRepeated)) {
            throw new AssertionError(
                    "HKDF derivation is not deterministic"
            );
        }

        System.out.println(
                "Key derivation test successful!"
        );

        System.out.println(
                "Proxy -> Server key size: "
                        + (proxyKey.length * 8) + " bits"
        );

        System.out.println(
                "Server -> Proxy key size: "
                        + (serverKey.length * 8) + " bits"
        );

        System.out.println(
                "Directional keys are different: "
                        + !Arrays.equals(proxyKey, serverKey)
        );

        System.out.println(
                "Repeated derivation matches: "
                        + Arrays.equals(
                        proxyKey, proxyKeyRepeated
                )
        );

        // Never print real session keys.
        Arrays.fill(proxyKey, (byte) 0);
        Arrays.fill(serverKey, (byte) 0);
        Arrays.fill(proxyKeyRepeated, (byte) 0);
    }
}
