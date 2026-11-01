import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.LinkOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.EnumSet;
import java.util.Set;

public final class IdentityKeyManager {

    private static final String ALGORITHM = "Ed25519";

    private IdentityKeyManager() {
        // Utility class
    }

    // Generate and save a new server identity.
    // Existing key files are never overwritten.
    public static KeyPair generateAndSave(
            Path privateKeyPath,
            Path publicKeyPath)
            throws GeneralSecurityException, IOException {

        if (privateKeyPath == null || publicKeyPath == null) {
            throw new IllegalArgumentException(
                    "Key paths cannot be null"
            );
        }

        if (privateKeyPath.toAbsolutePath().normalize()
                .equals(publicKeyPath.toAbsolutePath().normalize())) {
            throw new IllegalArgumentException(
                    "Private and public key paths must differ"
            );
        }

        KeyPair keyPair = DigitalSignature.generateKeyPair();

        byte[] privateKeyBytes =
                keyPair.getPrivate().getEncoded();

        byte[] publicKeyBytes =
                DigitalSignature.encodePublicKey(
                        keyPair.getPublic()
                );

        if (privateKeyBytes == null) {
            throw new GeneralSecurityException(
                    "Private key cannot be encoded"
            );
        }

        try {
            writePrivateKey(privateKeyPath, privateKeyBytes);

            try {
                Files.write(
                        publicKeyPath,
                        publicKeyBytes,
                        StandardOpenOption.CREATE_NEW,
                        StandardOpenOption.WRITE
                );
            } catch (IOException e) {
                Files.deleteIfExists(privateKeyPath);
                throw e;
            }

            return keyPair;

        } finally {
            java.util.Arrays.fill(
                    privateKeyBytes, (byte) 0
            );
        }
    }

    // Save the private key with restricted permissions
    // where the operating system supports POSIX permissions.
    private static void writePrivateKey(
            Path path,
            byte[] keyBytes)
            throws IOException {

        try {
            Set<PosixFilePermission> permissions =
                    EnumSet.of(
                            PosixFilePermission.OWNER_READ,
                            PosixFilePermission.OWNER_WRITE
                    );

            Files.createFile(
                    path,
                    java.nio.file.attribute.PosixFilePermissions
                            .asFileAttribute(permissions)
            );

            try {
                Files.write(
                        path,
                        keyBytes,
                        StandardOpenOption.WRITE
                );
            } catch (IOException e) {
                Files.deleteIfExists(path);
                throw e;
            }

        } catch (UnsupportedOperationException e) {
            // Windows typically uses ACLs rather than POSIX permissions.
            Files.write(
                    path,
                    keyBytes,
                    StandardOpenOption.CREATE_NEW,
                    StandardOpenOption.WRITE
            );
        }
    }

    // Load a stored private identity key.
    public static PrivateKey loadPrivateKey(Path path)
            throws GeneralSecurityException, IOException {

        if (path == null) {
            throw new IllegalArgumentException(
                    "Private key path cannot be null"
            );
        }

        if (Files.isSymbolicLink(path)) {
            throw new IOException(
                    "Symbolic links are not accepted"
            );
        }

        byte[] encoded = Files.readAllBytes(path);

        try {
            KeyFactory factory =
                    KeyFactory.getInstance(ALGORITHM);

            return factory.generatePrivate(
                    new PKCS8EncodedKeySpec(encoded)
            );

        } finally {
            java.util.Arrays.fill(encoded, (byte) 0);
        }
    }

    // Load a stored public identity key.
    public static PublicKey loadPublicKey(Path path)
            throws GeneralSecurityException, IOException {

        if (path == null) {
            throw new IllegalArgumentException(
                    "Public key path cannot be null"
            );
        }

        if (Files.isSymbolicLink(path)) {
            throw new IOException(
                    "Symbolic links are not accepted"
            );
        }

        return DigitalSignature.decodePublicKey(
                Files.readAllBytes(path)
        );
    }
}
