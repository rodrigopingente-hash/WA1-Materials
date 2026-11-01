import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

public class IdentityKeyManagerTest {

    public static void main(String[] args) throws Exception {

        // Create an isolated temporary directory.
        Path testDirectory =
                Files.createTempDirectory("3s-identity-test-");

        Path privateKeyPath =
                testDirectory.resolve("server-private.key");

        Path publicKeyPath =
                testDirectory.resolve("server-public.key");

        try {
            // 1. Generate and save identity keys.
            KeyPair originalIdentity =
                    IdentityKeyManager.generateAndSave(
                            privateKeyPath,
                            publicKeyPath
                    );

            if (!Files.exists(privateKeyPath)
                    || !Files.exists(publicKeyPath)) {
                throw new AssertionError(
                        "Identity key files were not created"
                );
            }

            // 2. Load the stored identity keys.
            PrivateKey loadedPrivateKey =
                    IdentityKeyManager.loadPrivateKey(
                            privateKeyPath
                    );

            PublicKey loadedPublicKey =
                    IdentityKeyManager.loadPublicKey(
                            publicKeyPath
                    );

            // 3. Verify that the public key is unchanged.
            if (!Arrays.equals(
                    originalIdentity.getPublic().getEncoded(),
                    loadedPublicKey.getEncoded()
            )) {
                throw new AssertionError(
                        "Loaded public key does not match"
                );
            }

            // 4. Sign using the loaded private key.
            byte[] message =
                    "3S-WA1-server-identity-test"
                            .getBytes(StandardCharsets.UTF_8);

            byte[] signature =
                    DigitalSignature.sign(
                            loadedPrivateKey,
                            message
                    );

            // 5. Verify using the loaded public key.
            boolean verified =
                    DigitalSignature.verify(
                            loadedPublicKey,
                            message,
                            signature
                    );

            if (!verified) {
                throw new AssertionError(
                        "Stored identity keys failed verification"
                );
            }

            // 6. Confirm existing keys cannot be overwritten.
            boolean overwriteRejected = false;

            try {
                IdentityKeyManager.generateAndSave(
                        privateKeyPath,
                        publicKeyPath
                );
            } catch (java.nio.file.FileAlreadyExistsException e) {
                overwriteRejected = true;
            }

            if (!overwriteRejected) {
                throw new AssertionError(
                        "Existing identity was overwritten"
                );
            }

            System.out.println(
                    "Identity key management test successful!"
            );

            System.out.println(
                    "Identity key files created: true"
            );

            System.out.println(
                    "Stored public key matches: true"
            );

            System.out.println(
                    "Loaded identity signature verified: true"
            );

            System.out.println(
                    "Existing identity overwrite rejected: true"
            );

            Arrays.fill(signature, (byte) 0);

        } finally {
            // Remove test files and directory.
            Files.deleteIfExists(privateKeyPath);
            Files.deleteIfExists(publicKeyPath);
            Files.deleteIfExists(testDirectory);
        }
    }
}
