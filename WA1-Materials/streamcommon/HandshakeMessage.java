import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

public final class HandshakeMessage {

    // Protocol version: 1.1
    public static final int VERSION = 1;
    public static final int RELEASE = 1;

    // Message types defined in WA1
    public static final int TYPE_CLIENT_HELLO = 1;
    public static final int TYPE_SERVER_HELLO = 2;
    public static final int TYPE_CLIENT_FINISH = 3;
    public static final int TYPE_STREAM_BLOCK = 4;
    public static final int TYPE_STREAM_END = 5;
    public static final int TYPE_ERROR = 255;

    // 2 + 2 + 1 + 4 bytes
    public static final int HEADER_SIZE = 9;

    // Defensive upper bound for a single message
    public static final int MAX_PAYLOAD_SIZE = 1024 * 1024;

    private final int type;
    private final byte[] payload;

    public HandshakeMessage(int type, byte[] payload) {

        if (!isValidType(type)) {
            throw new IllegalArgumentException(
                    "Invalid message type: " + type
            );
        }

        if (payload == null) {
            throw new IllegalArgumentException(
                    "Payload cannot be null"
            );
        }

        if (payload.length > MAX_PAYLOAD_SIZE) {
            throw new IllegalArgumentException(
                    "Payload exceeds maximum size"
            );
        }

        this.type = type;
        this.payload = payload.clone();
    }

    public int getType() {
        return type;
    }

    public byte[] getPayload() {
        return payload.clone();
    }

    public int getPayloadLength() {
        return payload.length;
    }

    private static boolean isValidType(int type) {
        return type == TYPE_CLIENT_HELLO
                || type == TYPE_SERVER_HELLO
                || type == TYPE_CLIENT_FINISH
                || type == TYPE_STREAM_BLOCK
                || type == TYPE_STREAM_END
                || type == TYPE_ERROR;
    }

    // Serialize and transmit one complete message.
    public void writeTo(OutputStream output)
            throws IOException {

        DataOutputStream out =
                new DataOutputStream(output);

        out.writeShort(VERSION);
        out.writeShort(RELEASE);
        out.writeByte(type);
        out.writeInt(payload.length);
        out.write(payload);
        out.flush();
    }

    // Read one complete message from the connection.
    public static HandshakeMessage readFrom(
            InputStream input) throws IOException {

        DataInputStream in =
                new DataInputStream(input);

        int version = in.readUnsignedShort();
        int release = in.readUnsignedShort();
        int type = in.readUnsignedByte();
        int payloadLength = in.readInt();

        if (version != VERSION || release != RELEASE) {
            throw new IOException(
                    "Unsupported protocol version: "
                            + version + "." + release
            );
        }

        if (!isValidType(type)) {
            throw new IOException(
                    "Unknown message type: " + type
            );
        }

        if (payloadLength < 0
                || payloadLength > MAX_PAYLOAD_SIZE) {
            throw new IOException(
                    "Invalid payload length: "
                            + payloadLength
            );
        }

        byte[] payload = new byte[payloadLength];

        try {
            in.readFully(payload);
        } catch (EOFException e) {
            throw new EOFException(
                    "Incomplete message payload"
            );
        }

        return new HandshakeMessage(type, payload);
    }

    @Override
    public String toString() {
        return "HandshakeMessage{" +
                "version=" + VERSION + "." + RELEASE +
                ", type=" + type +
                ", payloadLength=" + payload.length +
                '}';
    }

    @Override
    public boolean equals(Object obj) {

        if (this == obj) {
            return true;
        }

        if (!(obj instanceof HandshakeMessage other)) {
            return false;
        }

        return type == other.type
                && Arrays.equals(payload, other.payload);
    }

    @Override
    public int hashCode() {
        return 31 * type + Arrays.hashCode(payload);
    }
}
