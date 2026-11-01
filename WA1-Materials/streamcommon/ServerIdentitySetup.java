import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.util.Arrays;

public class ServerIdentitySetup {

    public static void main(String[] args) throws Exception {

        Path privateKeyPath = Paths.get(
                "streamserver",
                "keys",
                "server-private.key"
        );

        Path publicKeyPath = Paths.get(
                "streamserver",
                "keys",
                "server-public.key"
        );

        Path trustedKeyPath = Paths.get(
                "streamproxy",
                "keys",
                "trusted-server-public.key"
        );

        Files.createDirectories(privateKeyPath.getParent());
        Files.createDirectories(trustedKeyPath.getParent());

        boolean privateExists = Files.exists(privateKeyPath);
        boolean publicExists = Files.exists(publicKeyPath);

        if (!privateExists && !publicExists) {

            IdentityKeyManager.generateAndSave(
                    privateKeyPath,
                    publicKeyPath
            );

            System.out.println(
                    "New Ed25519 server identity generated."
            );

        } else if (privateExists && publicExists) {

            System.out.println(
                    "Existing server identity found."
            );

        } else {
            throw new IllegalStateException(
                    "Incomplete server identity: one key file is missing"
            );
        }

        PublicKey serverPublicKey =
                IdentityKeyManager.loadPublicKey(publicKeyPath);

        IdentityKeyManager.loadPrivateKey(privateKeyPath);

        byte[] expectedPublicKey =
                serverPublicKey.getEncoded();

        if (Files.exists(trustedKeyPath)) {

            byte[] trustedPublicKey =
                    Files.readAllBytes(trustedKeyPath);

            if (!Arrays.equals(
                    expectedPublicKey,
                    trustedPublicKey
            )) {
                throw new SecurityException(
                        "Trusted Proxy key differs from server identity"
                );
            }

            System.out.println(
                    "Existing trusted public key verified."
            );

        } else {

            Files.write(
                    trustedKeyPath,
                    expectedPublicKey,
                    java.nio.file.StandardOpenOption.CREATE_NEW
            );

            System.out.println(
                    "Trusted server public key installed for Proxy."
            );
        }

        System.out.println();
        System.out.println(
                "Server private key: "
                        + privateKeyPath.toAbsolutePath()
        );

        System.out.println(
                "Server public key: "
                        + publicKeyPath.toAbsolutePath()
        );

        System.out.println(
                "Proxy trusted key: "
                        + trustedKeyPath.toAbsolutePath()
        );

        System.out.println();
        System.out.println(
                "Server identity setup successful!"
        );
    }
}
