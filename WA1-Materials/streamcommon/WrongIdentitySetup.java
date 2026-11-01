
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;

public class WrongIdentitySetup {

    public static void main(String[] args) throws Exception {

        Path trustedKey = Paths.get(
                "streamproxy",
                "keys",
                "trusted-server-public.key"
        );

        Path backup = Paths.get(
                "streamproxy",
                "keys",
                "trusted-server-public.key.backup"
        );

        if (!Files.exists(backup)) {
            throw new IllegalStateException(
                    "Backup da chave original não encontrado."
            );
        }

        KeyPair wrongIdentity =
                DigitalSignature.generateKeyPair();

        Files.write(
                trustedKey,
                wrongIdentity.getPublic().getEncoded()
        );

        System.out.println(
                "Wrong Ed25519 public key installed for testing."
        );
        System.out.println(
                "Original trusted key safely backed up."
        );
    }
}
