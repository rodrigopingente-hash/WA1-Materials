import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

public class HandshakeMessageTest {

    public static void main(String[] args) throws Exception {

        String content = "AES/GCM/NULL/NULL";

        HandshakeMessage original =
                new HandshakeMessage(
                        HandshakeMessage.TYPE_CLIENT_HELLO,
                        content.getBytes(StandardCharsets.UTF_8)
                );

        ByteArrayOutputStream output =
                new ByteArrayOutputStream();

        original.writeTo(output);

        byte[] serialized = output.toByteArray();

        ByteArrayInputStream input =
                new ByteArrayInputStream(serialized);

        HandshakeMessage received =
                HandshakeMessage.readFrom(input);

        if (!original.equals(received)) {
            throw new AssertionError(
                    "Message serialization failed"
            );
        }

        System.out.println(
                "Handshake message test successful!"
        );

        System.out.println(
                "Serialized size: " + serialized.length
        );

        System.out.println(received);

        System.out.println(
                "Payload: " +
                        new String(
                                received.getPayload(),
                                StandardCharsets.UTF_8
                        )
        );
    }
}
