import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

public final class SecureHttpTransport {

    private static final int BLOCK_SIZE = 1024;
    private static final int MAX_HEADERS_SIZE = 16384;

    // Application-level message types.
    private static final byte TYPE_DATA = 1;
    private static final byte TYPE_END = 2;

    // One byte is reserved for the message type.
    private static final int MAX_DATA_SIZE = BLOCK_SIZE - 1;

    private final SecureChannel channel;

    private boolean sendFinished = false;
    private boolean receiveFinished = false;

    // Counts successfully authenticated DATA records (not raw TCP packets).
    private long receivedDataBlocks = 0;
    private long receivedDataBytes = 0;

    public SecureHttpTransport(SecureChannel channel) {

        if (channel == null) {
            throw new IllegalArgumentException(
                    "Secure channel cannot be null"
            );
        }

        this.channel = channel;
    }

    // Send a complete HTTP header block.
    public void sendHeaders(String headers)
            throws IOException, GeneralSecurityException {

        if (headers == null) {
            throw new IllegalArgumentException(
                    "HTTP headers cannot be null"
            );
        }

        byte[] bytes = headers.getBytes(
                StandardCharsets.US_ASCII
        );

        if (bytes.length > MAX_HEADERS_SIZE) {
            throw new IOException(
                    "HTTP headers exceed maximum size"
            );
        }

        sendBytes(bytes, 0, bytes.length);
    }

    // Receive HTTP headers until CRLF CRLF.
    public String receiveHeaders()
            throws IOException, GeneralSecurityException {

        ByteArrayOutputStream buffer =
                new ByteArrayOutputStream();

        byte[] delimiter = {
                '\r', '\n', '\r', '\n'
        };

        while (buffer.size() < MAX_HEADERS_SIZE) {

            byte[] block = receiveData();

            if (block == null) {
                throw new IOException(
                        "Transmission ended before HTTP headers"
                );
            }

            buffer.write(block);

            byte[] accumulated = buffer.toByteArray();

            if (endsWith(accumulated, delimiter)) {
                return new String(
                        accumulated,
                        StandardCharsets.US_ASCII
                );
            }

            if (accumulated.length > MAX_HEADERS_SIZE) {
                throw new IOException(
                        "HTTP headers exceed maximum size"
                );
            }
        }

        throw new IOException(
                "HTTP headers exceed maximum size"
        );
    }

    // Send an arbitrary byte array as encrypted blocks.
    public void sendBytes(
            byte[] data,
            int offset,
            int length)
            throws IOException, GeneralSecurityException {

        if (sendFinished) {
            throw new IOException(
                    "Transmission already finished"
            );
        }

        if (data == null
                || offset < 0
                || length < 0
                || offset > data.length - length) {
            throw new IllegalArgumentException(
                    "Invalid byte array range"
            );
        }

        int remaining = length;
        int position = offset;

        while (remaining > 0) {

            int count = Math.min(
                    remaining,
                    MAX_DATA_SIZE
            );

            byte[] record = new byte[count + 1];

            record[0] = TYPE_DATA;

            System.arraycopy(
                    data,
                    position,
                    record,
                    1,
                    count
            );

            channel.send(record);

            position += count;
            remaining -= count;
        }
    }

    // Receive one authenticated data block.
    // Returns null only after an authenticated END.
    public byte[] receiveData()
            throws IOException, GeneralSecurityException {

        if (receiveFinished) {
            return null;
        }

        byte[] record = channel.receive();

        if (record.length < 1) {
            throw new IOException(
                    "Empty application record"
            );
        }

        byte type = record[0];

        if (type == TYPE_END) {

            if (record.length != 1) {
                throw new IOException(
                        "Invalid END record"
                );
            }

            receiveFinished = true;
            return null;
        }

        if (type != TYPE_DATA) {
            throw new IOException(
                    "Unknown application record type"
            );
        }

        if (record.length == 1) {
            throw new IOException(
                    "Empty DATA record"
            );
        }

        byte[] data = Arrays.copyOfRange(
                record,
                1,
                record.length
        );
        receivedDataBlocks++;
        receivedDataBytes += data.length;
        return data;
    }

    // Send an authenticated end-of-message marker.
    public void finishSending()
            throws IOException, GeneralSecurityException {

        if (sendFinished) {
            throw new IOException(
                    "END already sent"
            );
        }

        channel.send(new byte[]{TYPE_END});
        sendFinished = true;
    }

    public long getReceivedDataBlocks() {
        return receivedDataBlocks;
    }

    public long getReceivedDataBytes() {
        return receivedDataBytes;
    }

    public boolean isSendFinished() {
        return sendFinished;
    }

    public boolean isReceiveFinished() {
        return receiveFinished;
    }

    private static boolean endsWith(
            byte[] data,
            byte[] suffix) {

        if (data.length < suffix.length) {
            return false;
        }

        for (int i = 0; i < suffix.length; i++) {

            if (data[data.length - suffix.length + i]
                    != suffix[i]) {
                return false;
            }
        }

        return true;
    }
}
