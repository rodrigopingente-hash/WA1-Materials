import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;

public final class SecureRecord {

    // AES-128, AES-192 and AES-256 session keys are supported.
    private static final int NONCE_LENGTH = 12;
    private static final int TAG_LENGTH_BITS = 128;
    private static final int TAG_LENGTH_BYTES = 16;

    private static final int MAX_PLAINTEXT_SIZE = 1024;
    private static final int MAX_RECORD_SIZE =
            8 + MAX_PLAINTEXT_SIZE + TAG_LENGTH_BYTES;

    private static final byte[] PROTOCOL_LABEL =
            "3S-WA1-RECORD-v1".getBytes(
                    StandardCharsets.US_ASCII
            );

    private final SecretKeySpec key;
    private final byte[] noncePrefix;

    private long sendSequence = 0;
    private long receiveSequence = 0;

    public SecureRecord(
            byte[] sessionKey,
            byte[] transcriptHash,
            String direction)
            throws GeneralSecurityException {

        if (sessionKey == null
                || (sessionKey.length != 16 && sessionKey.length != 24 && sessionKey.length != 32)) {
            throw new IllegalArgumentException(
                    "AES requires a 16-, 24- or 32-byte key"
            );
        }

        if (transcriptHash == null
                || transcriptHash.length != 32) {
            throw new IllegalArgumentException(
                    "Transcript hash must contain 32 bytes"
            );
        }

        if (!"PROXY_TO_SERVER".equals(direction)
                && !"SERVER_TO_PROXY".equals(direction)) {
            throw new IllegalArgumentException(
                    "Invalid record direction"
            );
        }

        this.key = new SecretKeySpec(
                sessionKey.clone(),
                "AES"
        );

        // The nonce prefix is bound to the
        // handshake transcript and direction.
        MessageDigest digest =
                MessageDigest.getInstance("SHA-256");

        digest.update(PROTOCOL_LABEL);
        digest.update(
                direction.getBytes(StandardCharsets.US_ASCII)
        );
        digest.update(transcriptHash);

        byte[] hash = digest.digest();

        this.noncePrefix = Arrays.copyOf(hash, 4);
        Arrays.fill(hash, (byte) 0);
    }

    // Encrypt one plaintext block.
    public synchronized byte[] encrypt(
            byte[] plaintext)
            throws GeneralSecurityException {

        if (plaintext == null
                || plaintext.length > MAX_PLAINTEXT_SIZE) {
            throw new IllegalArgumentException(
                    "Invalid plaintext block size"
            );
        }

        if (sendSequence == Long.MAX_VALUE) {
            throw new SecurityException(
                    "Send sequence exhausted"
            );
        }

        long sequence = sendSequence;

        byte[] nonce = buildNonce(sequence);

        byte[] aad = buildAAD(
                sequence,
                plaintext.length + TAG_LENGTH_BYTES
        );

        Cipher cipher =
                Cipher.getInstance("AES/GCM/NoPadding");

        cipher.init(
                Cipher.ENCRYPT_MODE,
                key,
                new GCMParameterSpec(
                        TAG_LENGTH_BITS,
                        nonce
                )
        );

        cipher.updateAAD(aad);

        byte[] ciphertext =
                cipher.doFinal(plaintext);

        ByteBuffer record =
                ByteBuffer.allocate(
                        8 + ciphertext.length
                );

        record.putLong(sequence);
        record.put(ciphertext);

        sendSequence++;

        return record.array();
    }

    // Decrypt and authenticate one record.
    public synchronized byte[] decrypt(
            byte[] record)
            throws GeneralSecurityException {

        if (record == null
                || record.length < 8 + TAG_LENGTH_BYTES
                || record.length > MAX_RECORD_SIZE) {
            throw new IllegalArgumentException(
                    "Invalid encrypted record size"
            );
        }

        ByteBuffer buffer = ByteBuffer.wrap(record);

        long sequence = buffer.getLong();

        if (sequence != receiveSequence) {
            throw new SecurityException(
                    "Unexpected record sequence: "
                            + sequence
                            + " (expected "
                            + receiveSequence + ")"
            );
        }

        byte[] ciphertext =
                new byte[buffer.remaining()];

        buffer.get(ciphertext);

        byte[] nonce = buildNonce(sequence);

        byte[] aad = buildAAD(
                sequence,
                ciphertext.length
        );

        Cipher cipher =
                Cipher.getInstance("AES/GCM/NoPadding");

        cipher.init(
                Cipher.DECRYPT_MODE,
                key,
                new GCMParameterSpec(
                        TAG_LENGTH_BITS,
                        nonce
                )
        );

        cipher.updateAAD(aad);

        // If authentication fails, doFinal throws
        // AEADBadTagException and the sequence
        // counter is not advanced.
        byte[] plaintext = cipher.doFinal(ciphertext);

        receiveSequence++;

        return plaintext;
    }

    // Send an encrypted record over a TCP stream.
    public void send(
            OutputStream out,
            byte[] plaintext)
            throws IOException, GeneralSecurityException {

        byte[] record = encrypt(plaintext);

        DataOutputStream data =
                new DataOutputStream(out);

        data.writeInt(record.length);
        data.write(record);
        data.flush();
    }

    // Receive and decrypt one TCP record.
    public byte[] receive(
            InputStream in)
            throws IOException, GeneralSecurityException {

        DataInputStream data =
                new DataInputStream(in);

        int length = data.readInt();

        if (length < 8 + TAG_LENGTH_BYTES
                || length > MAX_RECORD_SIZE) {
            throw new IOException(
                    "Invalid TCP record length"
            );
        }

        byte[] record = new byte[length];
        data.readFully(record);

        return decrypt(record);
    }

    private byte[] buildNonce(long sequence) {

        ByteBuffer nonce =
                ByteBuffer.allocate(NONCE_LENGTH);

        nonce.put(noncePrefix);
        nonce.putLong(sequence);

        return nonce.array();
    }

    private byte[] buildAAD(
            long sequence,
            int ciphertextLength) {

        ByteBuffer aad =
                ByteBuffer.allocate(
                        PROTOCOL_LABEL.length + 8 + 4
                );

        aad.put(PROTOCOL_LABEL);
        aad.putLong(sequence);
        aad.putInt(ciphertextLength);

        return aad.array();
    }

    public long getSendSequence() {
        return sendSequence;
    }

    public long getReceiveSequence() {
        return receiveSequence;
    }
}
