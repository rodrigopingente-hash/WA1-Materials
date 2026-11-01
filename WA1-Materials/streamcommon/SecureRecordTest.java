import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

public class SecureRecordTest {

    public static void main(String[] args) throws Exception {

        System.out.println(
                "========================================"
        );
        System.out.println(
                "3S WA1 - Secure Record Tests"
        );
        System.out.println(
                "========================================"
        );

        SecureRandom random = new SecureRandom();

        byte[] sessionKey = new byte[32];
        byte[] transcriptHash = new byte[32];

        random.nextBytes(sessionKey);
        random.nextBytes(transcriptHash);

        SecureRecord sender = new SecureRecord(
                sessionKey,
                transcriptHash,
                "PROXY_TO_SERVER"
        );

        SecureRecord receiver = new SecureRecord(
                sessionKey,
                transcriptHash,
                "PROXY_TO_SERVER"
        );

        byte[] plaintext =
                "Secure video streaming block"
                        .getBytes(StandardCharsets.UTF_8);

        // ========================================
        // TEST 1 - Encryption and decryption
        // ========================================

        byte[] encrypted = sender.encrypt(plaintext);
        byte[] decrypted = receiver.decrypt(encrypted);

        if (!Arrays.equals(plaintext, decrypted)) {
            throw new AssertionError(
                    "Encryption/decryption failed"
            );
        }

        System.out.println(
                "\nEncryption and decryption: PASSED"
        );

        // ========================================
        // TEST 2 - Ciphertext differs from plaintext
        // ========================================

        if (Arrays.equals(plaintext, encrypted)) {
            throw new AssertionError(
                    "Plaintext was not encrypted"
            );
        }

        System.out.println(
                "Plaintext confidentiality check: PASSED"
        );

        // ========================================
        // TEST 3 - Modified ciphertext
        // ========================================

        byte[] secondRecord = sender.encrypt(plaintext);

        byte[] modified = secondRecord.clone();
        modified[modified.length - 1] ^= 0x01;

        boolean modificationRejected = false;

        try {
            receiver.decrypt(modified);
        } catch (javax.crypto.AEADBadTagException e) {
            modificationRejected = true;
        }

        if (!modificationRejected) {
            throw new AssertionError(
                    "Modified ciphertext was accepted"
            );
        }

        System.out.println(
                "Modified ciphertext: REJECTED"
        );

        // ========================================
        // TEST 4 - Valid record after failed auth
        // ========================================

        byte[] recovered = receiver.decrypt(secondRecord);

        if (!Arrays.equals(plaintext, recovered)) {
            throw new AssertionError(
                    "Valid record recovery failed"
            );
        }

        System.out.println(
                "Valid record after failed auth: PASSED"
        );

        // ========================================
        // TEST 5 - Replay attack
        // ========================================

        boolean replayRejected = false;

        try {
            receiver.decrypt(secondRecord);
        } catch (SecurityException e) {
            replayRejected = true;
        }

        if (!replayRejected) {
            throw new AssertionError(
                    "Replay attack was accepted"
            );
        }

        System.out.println(
                "Replay attack: REJECTED"
        );

        // ========================================
        // TEST 6 - Out-of-order record
        // ========================================

        byte[] thirdRecord = sender.encrypt(plaintext);
        byte[] fourthRecord = sender.encrypt(plaintext);

        boolean outOfOrderRejected = false;

        try {
            receiver.decrypt(fourthRecord);
        } catch (SecurityException e) {
            outOfOrderRejected = true;
        }

        if (!outOfOrderRejected) {
            throw new AssertionError(
                    "Out-of-order record was accepted"
            );
        }

        System.out.println(
                "Out-of-order record: REJECTED"
        );

        // The correct record must still work.
        receiver.decrypt(thirdRecord);
        receiver.decrypt(fourthRecord);

        // ========================================
        // TEST 7 - Incorrect encryption key
        // ========================================

        byte[] wrongKey = sessionKey.clone();
        wrongKey[0] ^= 0x01;

        SecureRecord wrongReceiver = new SecureRecord(
                wrongKey,
                transcriptHash,
                "PROXY_TO_SERVER"
        );

        SecureRecord freshSender = new SecureRecord(
                sessionKey,
                transcriptHash,
                "PROXY_TO_SERVER"
        );

        byte[] testRecord = freshSender.encrypt(plaintext);

        boolean wrongKeyRejected = false;

        try {
            wrongReceiver.decrypt(testRecord);
        } catch (javax.crypto.AEADBadTagException e) {
            wrongKeyRejected = true;
        }

        if (!wrongKeyRejected) {
            throw new AssertionError(
                    "Incorrect encryption key was accepted"
            );
        }

        System.out.println(
                "Incorrect encryption key: REJECTED"
        );

        // ========================================
        // TEST 8 - TCP record transmission
        // ========================================

        SecureRecord tcpSender = new SecureRecord(
                sessionKey,
                transcriptHash,
                "SERVER_TO_PROXY"
        );

        SecureRecord tcpReceiver = new SecureRecord(
                sessionKey,
                transcriptHash,
                "SERVER_TO_PROXY"
        );

        ByteArrayOutputStream network =
                new ByteArrayOutputStream();

        tcpSender.send(network, plaintext);

        ByteArrayInputStream incoming =
                new ByteArrayInputStream(
                        network.toByteArray()
                );

        byte[] received = tcpReceiver.receive(incoming);

        if (!Arrays.equals(plaintext, received)) {
            throw new AssertionError(
                    "TCP record transmission failed"
            );
        }

        System.out.println(
                "TCP record transmission: PASSED"
        );

        // ========================================
        // FINAL RESULT
        // ========================================

        System.out.println(
                "\n========================================"
        );

        System.out.println(
                "All secure record tests passed!"
        );

        System.out.println(
                "========================================"
        );

        Arrays.fill(sessionKey, (byte) 0);
        Arrays.fill(wrongKey, (byte) 0);
    }
}
