import java.io.IOException;
import java.io.RandomAccessFile;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.util.concurrent.Executors;

public class OriginSocketServer {

    static final int BLOCK_SIZE = 1024;

    public static void main(String[] args) throws Exception {

        int port = args.length > 0
                ? Integer.parseInt(args[0]) : 8081;

        Path root = Paths.get(
                args.length > 1 ? args[1] : "streamserver/media"
        ).toAbsolutePath().normalize();

        Path privateKeyPath = Paths.get(
                "streamserver", "keys", "server-private.key"
        );

        PrivateKey privateKey =
                IdentityKeyManager.loadPrivateKey(privateKeyPath);
        CryptoConfig serverConfig = CryptoConfig.load(
                "streamserver/sservercrypto.config"
        );

        System.out.println(
                "Server cryptographic configuration: "
                        + serverConfig.getCipherSuiteIdentifier()
        );
        try (ServerSocket server = new ServerSocket(port)) {

            System.out.println(
                    "Secure Origin Server listening on port " + port
            );
            System.out.println("Media directory: " + root);
            System.out.println("Authentication: Ed25519");
            System.out.println("Secure channel: X25519 + AES-256-GCM");

            var pool = Executors.newCachedThreadPool();

            while (true) {
                Socket client = server.accept();

                pool.submit(() ->
                        handle(client, root, privateKey, serverConfig)
                );
            }
        }
    }

    static void handle(
            Socket socket,
            Path root,
            PrivateKey privateKey,
            CryptoConfig serverConfig) {

        try (socket) {

            socket.setSoTimeout(30000);

            try (SecureChannel channel =
                         SecureChannel.accept(
                                 socket,
                                 privateKey,
                                 serverConfig
                         )) {

                SecureHttpTransport transport =
                        new SecureHttpTransport(channel);

                String request = transport.receiveHeaders();

                // Require an authenticated end of request.
                if (transport.receiveData() != null) {
                    throw new IOException(
                            "Unexpected HTTP request body"
                    );
                }

                String[] lines = request.split("\r\n");

                if (lines.length == 0
                        || !lines[0].startsWith("GET ")) {

                    sendStatus(
                            transport,
                            400,
                            "Bad Request",
                            0
                    );
                    return;
                }

                String[] requestParts = lines[0].split(" ");

                if (requestParts.length < 3) {
                    sendStatus(
                            transport,
                            400,
                            "Bad Request",
                            0
                    );
                    return;
                }

                String path = requestParts[1];
                String rangeHeader = null;

                for (int i = 1; i < lines.length; i++) {

                    if (lines[i].toLowerCase()
                            .startsWith("range:")) {

                        rangeHeader = lines[i]
                                .substring(6)
                                .trim();
                    }
                }

                if (!path.startsWith("/media/")) {
                    sendStatus(
                            transport,
                            404,
                            "Not Found",
                            0
                    );
                    return;
                }

                String name =
                        path.substring("/media/".length());

                Path file = root.resolve(name).normalize();

                if (!file.startsWith(root)
                        || !Files.isRegularFile(file)) {

                    sendStatus(
                            transport,
                            404,
                            "Not Found",
                            0
                    );
                    return;
                }

                serveFile(transport, file, rangeHeader);

            }

        } catch (Exception e) {

            System.err.println(
                    "Secure Origin connection failed: "
                            + e.getMessage()
            );
        }
    }

    static void serveFile(
            SecureHttpTransport transport,
            Path file,
            String rangeHeader) throws Exception {

        long size = Files.size(file);

        long start = 0;
        long end = size - 1;

        boolean partial = false;

        if (rangeHeader != null
                && rangeHeader.startsWith("bytes=")
                && !rangeHeader.contains(",")) {

            try {

                String[] p = rangeHeader
                        .substring(6)
                        .trim()
                        .split("-", -1);

                long s;
                long e = end;

                if (p[0].isEmpty()) {

                    s = Math.max(
                            0,
                            size - Long.parseLong(p[1])
                    );

                } else {

                    s = Long.parseLong(p[0]);

                    if (p.length > 1
                            && !p[1].isEmpty()) {

                        e = Math.min(
                                Long.parseLong(p[1]),
                                size - 1
                        );
                    }
                }

                if (s > e || s >= size) {

                    sendHeaders(
                            transport,
                            416,
                            "Range Not Satisfiable",
                            0,
                            null,
                            "Content-Range: bytes */"
                                    + size + "\r\n"
                    );

                    transport.finishSending();
                    return;
                }

                start = s;
                end = e;
                partial = true;

            } catch (NumberFormatException
                     | ArrayIndexOutOfBoundsException ignored) {

                // Invalid Range: serve the full file.
            }
        }

        long length = end - start + 1;

        String extraHeaders =
                "Accept-Ranges: bytes\r\n"
                        + (partial
                        ? "Content-Range: bytes "
                        + start + "-" + end + "/" + size + "\r\n"
                        : "");

        sendHeaders(
                transport,
                partial ? 206 : 200,
                partial ? "Partial Content" : "OK",
                length,
                "video/mp4",
                extraHeaders
        );

        try (RandomAccessFile raf =
                     new RandomAccessFile(file.toFile(), "r")) {

            raf.seek(start);

            byte[] block = new byte[BLOCK_SIZE];
            long remaining = length;

            while (remaining > 0) {

                int n = raf.read(
                        block,
                        0,
                        (int) Math.min(
                                block.length,
                                remaining
                        )
                );

                if (n < 0) {
                    throw new IOException(
                            "Unexpected end of media file"
                    );
                }

                transport.sendBytes(block, 0, n);

                remaining -= n;
            }
        }

        transport.finishSending();
    }

    static void sendStatus(
            SecureHttpTransport transport,
            int code,
            String reason,
            long contentLength) throws Exception {

        sendHeaders(
                transport,
                code,
                reason,
                contentLength,
                null,
                null
        );

        transport.finishSending();
    }

    static void sendHeaders(
            SecureHttpTransport transport,
            int code,
            String reason,
            long contentLength,
            String contentType,
            String extraHeaders) throws Exception {

        StringBuilder sb = new StringBuilder();

        sb.append("HTTP/1.1 ")
                .append(code)
                .append(' ')
                .append(reason)
                .append("\r\n");

        if (contentType != null) {
            sb.append("Content-Type: ")
                    .append(contentType)
                    .append("\r\n");
        }

        sb.append("Content-Length: ")
                .append(contentLength)
                .append("\r\n");

        sb.append("Connection: close\r\n");

        if (extraHeaders != null) {
            sb.append(extraHeaders);
        }

        sb.append("\r\n");

        transport.sendHeaders(sb.toString());
    }
}
