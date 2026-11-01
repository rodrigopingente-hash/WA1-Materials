import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.concurrent.*;

public class SecureHttpTransportTest {

    private static final String REQUEST =
            "GET /media/sample.mp4 HTTP/1.1\r\n" +
                    "Host: localhost:8081\r\n" +
                    "Range: bytes=0-2047\r\n" +
                    "\r\n";

    private static final String RESPONSE =
            "HTTP/1.1 206 Partial Content\r\n" +
                    "Content-Type: video/mp4\r\n" +
                    "Content-Length: 2048\r\n" +
                    "Content-Range: bytes 0-2047/4096\r\n" +
                    "\r\n";

    public static void main(String[] args) throws Exception {

        System.out.println(
                "========================================"
        );
        System.out.println(
                "3S WA1 - Secure HTTP Transport Tests"
        );
        System.out.println(
                "========================================"
        );

        KeyPair identity =
                DigitalSignature.generateKeyPair();

        ExecutorService executor =
                Executors.newSingleThreadExecutor();

        try (ServerSocket listener = new ServerSocket(0)) {

            listener.setSoTimeout(5000);

            Future<Boolean> serverFuture =
                    executor.submit(() -> {

                        try (Socket socket = listener.accept()) {

                            socket.setSoTimeout(5000);

                            try (SecureChannel channel =
                                         SecureChannel.accept(
                                                 socket,
                                                 identity.getPrivate()
                                         )) {

                                SecureHttpTransport transport =
                                        new SecureHttpTransport(channel);

                                String request =
                                        transport.receiveHeaders();

                                if (!REQUEST.equals(request)) {
                                    throw new AssertionError(
                                            "HTTP request mismatch"
                                    );
                                }

                                if (transport.receiveData() != null) {
                                    throw new AssertionError(
                                            "Unexpected request body"
                                    );
                                }

                                if (!transport.isReceiveFinished()) {
                                    throw new AssertionError(
                                            "Request END not received"
                                    );
                                }

                                transport.sendHeaders(RESPONSE);

                                byte[] video = new byte[2048];

                                for (int i = 0;
                                     i < video.length; i++) {
                                    video[i] = (byte) (i % 256);
                                }

                                transport.sendBytes(
                                        video,
                                        0,
                                        video.length
                                );

                                transport.finishSending();

                                return true;
                            }
                        }
                    });

            try (Socket socket =
                         new Socket(
                                 "localhost",
                                 listener.getLocalPort()
                         )) {

                socket.setSoTimeout(5000);

                try (SecureChannel channel =
                             SecureChannel.connect(
                                     socket,
                                     identity.getPublic()
                             )) {

                    SecureHttpTransport transport =
                            new SecureHttpTransport(channel);

                    System.out.println(
                            "\nAuthenticated TCP channel: PASSED"
                    );

                    transport.sendHeaders(REQUEST);
                    transport.finishSending();

                    System.out.println(
                            "Encrypted HTTP request: PASSED"
                    );

                    String headers =
                            transport.receiveHeaders();

                    if (!RESPONSE.equals(headers)) {
                        throw new AssertionError(
                                "HTTP response headers mismatch"
                        );
                    }

                    System.out.println(
                            "Encrypted HTTP response headers: PASSED"
                    );

                    byte[] receivedVideo = new byte[2048];
                    int position = 0;

                    byte[] block;

                    while ((block = transport.receiveData()) != null) {

                        if (position + block.length
                                > receivedVideo.length) {
                            throw new AssertionError(
                                    "Video response too large"
                            );
                        }

                        System.arraycopy(
                                block,
                                0,
                                receivedVideo,
                                position,
                                block.length
                        );

                        position += block.length;
                    }

                    if (position != receivedVideo.length) {
                        throw new AssertionError(
                                "Video response truncated"
                        );
                    }

                    for (int i = 0;
                         i < receivedVideo.length; i++) {

                        if (receivedVideo[i]
                                != (byte) (i % 256)) {
                            throw new AssertionError(
                                    "Video block integrity failed"
                            );
                        }
                    }

                    System.out.println(
                            "Encrypted video streaming: PASSED"
                    );

                    if (!transport.isReceiveFinished()) {
                        throw new AssertionError(
                                "Authenticated END missing"
                        );
                    }

                    System.out.println(
                            "Authenticated end of transmission: PASSED"
                    );
                }
            }

            if (!serverFuture.get(5, TimeUnit.SECONDS)) {
                throw new AssertionError(
                        "Server-side validation failed"
                );
            }

            System.out.println(
                    "\n========================================"
            );
            System.out.println(
                    "All secure HTTP transport tests passed!"
            );
            System.out.println(
                    "========================================"
            );

        } finally {
            executor.shutdownNow();
        }

        testInterruptedTransmission();
    }

    private static void testInterruptedTransmission()
            throws Exception {

        KeyPair identity =
                DigitalSignature.generateKeyPair();

        ExecutorService executor =
                Executors.newSingleThreadExecutor();

        try (ServerSocket listener = new ServerSocket(0)) {

            listener.setSoTimeout(5000);

            Future<?> serverFuture = executor.submit(() -> {

                try (Socket socket = listener.accept();
                     SecureChannel channel =
                             SecureChannel.accept(
                                     socket,
                                     identity.getPrivate()
                             )) {

                    socket.setSoTimeout(5000);

                    SecureHttpTransport transport =
                            new SecureHttpTransport(channel);

                    transport.sendHeaders(RESPONSE);

                    transport.sendBytes(
                            new byte[100],
                            0,
                            100
                    );

                    // Deliberately close without TYPE_END.

                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });

            try (Socket socket =
                         new Socket(
                                 "localhost",
                                 listener.getLocalPort()
                         )) {

                socket.setSoTimeout(5000);

                try (SecureChannel channel =
                             SecureChannel.connect(
                                     socket,
                                     identity.getPublic()
                             )) {

                    SecureHttpTransport transport =
                            new SecureHttpTransport(channel);

                    transport.receiveHeaders();

                    boolean rejected = false;

                    try {
                        while (transport.receiveData() != null) {
                            // Read until END or connection failure.
                        }
                    } catch (IOException e) {
                        rejected = true;
                    }

                    if (!rejected) {
                        throw new AssertionError(
                                "Truncated transmission accepted"
                        );
                    }

                    System.out.println(
                            "Interrupted transmission: REJECTED"
                    );
                }
            }

            serverFuture.get(5, TimeUnit.SECONDS);

        } finally {
            executor.shutdownNow();
        }
    }
}
