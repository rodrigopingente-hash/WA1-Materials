import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.util.concurrent.*;

public class SecureChannelTest {

    public static void main(String[] args) throws Exception {

        System.out.println(
                "========================================"
        );
        System.out.println(
                "3S WA1 - Secure Channel Tests"
        );
        System.out.println(
                "========================================"
        );

        KeyPair serverIdentity =
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
                                                 serverIdentity.getPrivate()
                                         )) {

                                String request =
                                        channel.receiveText();

                                if (!request.equals(
                                        "GET /media/sample.mp4"
                                )) {
                                    throw new AssertionError(
                                            "Incorrect decrypted request"
                                    );
                                }

                                channel.sendText(
                                        "HTTP/1.1 200 OK"
                                );

                                byte[] videoBlock = new byte[1024];

                                for (int i = 0;
                                     i < videoBlock.length;
                                     i++) {
                                    videoBlock[i] =
                                            (byte) (i % 256);
                                }

                                channel.send(videoBlock);

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
                                     serverIdentity.getPublic()
                             )) {

                    System.out.println(
                            "\nSecure TCP channel established: PASSED"
                    );

                    channel.sendText(
                            "GET /media/sample.mp4"
                    );

                    System.out.println(
                            "Encrypted request sent: PASSED"
                    );

                    String response =
                            channel.receiveText();

                    if (!response.equals(
                            "HTTP/1.1 200 OK"
                    )) {
                        throw new AssertionError(
                                "Incorrect server response"
                        );
                    }

                    System.out.println(
                            "Encrypted response received: PASSED"
                    );

                    byte[] videoBlock = channel.receive();

                    if (videoBlock.length != 1024) {
                        throw new AssertionError(
                                "Incorrect video block size"
                        );
                    }

                    for (int i = 0;
                         i < videoBlock.length;
                         i++) {

                        if (videoBlock[i]
                                != (byte) (i % 256)) {
                            throw new AssertionError(
                                    "Video block integrity failed"
                            );
                        }
                    }

                    System.out.println(
                            "Encrypted video block received: PASSED"
                    );

                    if (!channel.isOpen()) {
                        throw new AssertionError(
                                "Secure channel unexpectedly closed"
                        );
                    }

                    System.out.println(
                            "Secure channel state: PASSED"
                    );
                }
            }

            if (!serverFuture.get(
                    5,
                    TimeUnit.SECONDS
            )) {
                throw new AssertionError(
                        "Server-side test failed"
                );
            }

            System.out.println(
                    "\n========================================"
            );

            System.out.println(
                    "All secure channel tests passed!"
            );

            System.out.println(
                    "========================================"
            );

        } finally {
            executor.shutdownNow();
        }
    }
}
