import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

public final class KeyDerivation {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final int HASH_LENGTH = 32;

    private KeyDerivation() {
        // Utility class
    }

    // HKDF-Extract (RFC 5869)
    public static byte[] extract(byte[] salt, byte[] ikm)
            throws GeneralSecurityException {

        if (ikm == null || ikm.length == 0) {
            throw new IllegalArgumentException(
                    "Input key material cannot be empty"
            );
        }

        byte[] effectiveSalt =
                (salt == null || salt.length == 0)
                        ? new byte[HASH_LENGTH]
                        : salt;

        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(new SecretKeySpec(
                effectiveSalt, HMAC_ALGORITHM
        ));

        return mac.doFinal(ikm);
    }

    // HKDF-Expand (RFC 5869)
    public static byte[] expand(
            byte[] prk,
            byte[] info,
            int outputLength)
            throws GeneralSecurityException {

        if (prk == null || prk.length < HASH_LENGTH) {
            throw new IllegalArgumentException(
                    "Invalid pseudorandom key"
            );
        }

        if (outputLength < 1
                || outputLength > 255 * HASH_LENGTH) {
            throw new IllegalArgumentException(
                    "Invalid output length"
            );
        }

        byte[] context =
                info == null ? new byte[0] : info;

        int blocks =
                (outputLength + HASH_LENGTH - 1)
                        / HASH_LENGTH;

        byte[] output = new byte[outputLength];
        byte[] previous = new byte[0];

        int offset = 0;

        for (int i = 1; i <= blocks; i++) {

            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(
                    prk, HMAC_ALGORITHM
            ));

            mac.update(previous);
            mac.update(context);
            mac.update((byte) i);

            previous = mac.doFinal();

            int bytesToCopy = Math.min(
                    HASH_LENGTH,
                    outputLength - offset
            );

            System.arraycopy(
                    previous, 0,
                    output, offset,
                    bytesToCopy
            );

            offset += bytesToCopy;
        }

        return output;
    }

    // Complete HKDF operation
    public static byte[] deriveKey(
            byte[] sharedSecret,
            byte[] salt,
            String context,
            int keyLength)
            throws GeneralSecurityException {

        if (context == null || context.isBlank()) {
            throw new IllegalArgumentException(
                    "Key derivation context cannot be empty"
            );
        }

        byte[] prk = extract(salt, sharedSecret);

        try {
            return expand(
                    prk,
                    context.getBytes(StandardCharsets.UTF_8),
                    keyLength
            );
        } finally {
            Arrays.fill(prk, (byte) 0);
        }
    }

    // Derive a direction-specific session key.
    public static byte[] deriveSessionKey(
            byte[] sharedSecret,
            byte[] sessionSalt,
            byte[] transcriptHash,
            String direction,
            int keySizeBits)
            throws GeneralSecurityException {

        if (transcriptHash == null
                || transcriptHash.length != HASH_LENGTH) {
            throw new IllegalArgumentException(
                    "Transcript hash must be 32 bytes"
            );
        }

        if (!direction.equals("PROXY_TO_SERVER")
                && !direction.equals("SERVER_TO_PROXY")) {
            throw new IllegalArgumentException(
                    "Invalid key direction"
            );
        }

        if (keySizeBits != 128
                && keySizeBits != 192
                && keySizeBits != 256) {
            throw new IllegalArgumentException(
                    "Unsupported AES key size"
            );
        }

        String context = "3S-WA1-v1.1/"
                + direction + "/"
                + java.util.HexFormat.of()
                .formatHex(transcriptHash);

        return deriveKey(
                sharedSecret,
                sessionSalt,
                context,
                keySizeBits / 8
        );
    }
}
