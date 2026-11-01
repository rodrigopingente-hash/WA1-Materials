import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.util.concurrent.Executors;

public class ProxySocketServer {

    static final int BLOCK_SIZE = 1024;

    static final String INDEX_HTML = """
            <!doctype html>
            <html>
            <head>
              <meta charset="utf-8">
              <title>3S WA1 - Secure Video Streaming</title>
            </head>
            <body style="font-family:sans-serif;max-width:900px;margin:2rem auto">
              <h1>Secure Video Streaming</h1>
              <p>Browser to Proxy: HTTP</p>
              <p>Proxy to Origin: X25519 + Ed25519 + AES-256-GCM</p>
              <p>File:
                <input id="f" value="sample.mp4">
                <button onclick="load()">Load</button>
              </p>
              <video id="v" controls preload="metadata"
                     style="width:100%"></video>
              <script>
                function load() {
                  const v = document.getElementById('v');
                  v.src = '/video/' +
                    encodeURIComponent(
                      document.getElementById('f').value
                    );
                  v.load();
                }
                load();
              </script>
            </body>
            </html>
            """;

    public static void main(String[] args) throws Exception {

        int port = args.length > 0
                ? Integer.parseInt(args[0]) : 8080;

        String originHost = args.length > 1
                ? args[1] : "localhost";

        int originPort = args.length > 2
                ? Integer.parseInt(args[2]) : 8081;

        Path trustedKeyPath = Paths.get(
                "streamproxy",
                "keys",
                "trusted-server-public.key"
        );

        PublicKey trustedServerKey =
                IdentityKeyManager.loadPublicKey(
                        trustedKeyPath
                );
        CryptoConfig proxyConfig = CryptoConfig.load(
                "streamproxy/proxycrypto.config"
        );

        System.out.println(
                "Proxy cryptographic configuration: "
                        + proxyConfig.getCipherSuiteIdentifier()
        );
        try (ServerSocket server = new ServerSocket(port)) {

            System.out.println(
                    "Secure Proxy running at http://localhost:"
                            + port + "/"
            );

            System.out.println(
                    "Secure Origin: "
                            + originHost + ":" + originPort
            );

            System.out.println(
                    "Trusted Origin identity loaded: Ed25519"
            );

            var pool = Executors.newCachedThreadPool();

            while (true) {

                Socket browser = server.accept();

                pool.submit(() ->
                        handle(
                                browser,
                                originHost,
                                originPort,
                                trustedServerKey,
                                proxyConfig
                        )
                );
            }
        }
    }

    static void handle(
            Socket browser,
            String originHost,
            int originPort,
            PublicKey trustedServerKey,
            CryptoConfig proxyConfig) {

        try (browser) {

            browser.setSoTimeout(30000);

            InputStream in = browser.getInputStream();
            OutputStream out = browser.getOutputStream();

            String requestLine = HttpUtil.readLine(in);

            if (requestLine == null
                    || !requestLine.startsWith("GET ")) {

                writeSimpleStatus(
                        out,
                        400,
                        "Bad Request"
                );
                return;
            }

            String[] requestParts =
                    requestLine.split(" ");

            if (requestParts.length < 3) {
                writeSimpleStatus(
                        out,
                        400,
                        "Bad Request"
                );
                return;
            }

            String path = requestParts[1];

            String rangeHeader = null;
            String line;

            while ((line = HttpUtil.readLine(in)) != null
                    && !line.isEmpty()) {

                int c = line.indexOf(':');

                if (c > 0
                        && line.substring(0, c)
                        .equalsIgnoreCase("Range")) {

                    rangeHeader =
                            line.substring(c + 1).trim();
                }
            }

            if (path.equals("/") || path.isEmpty()) {
                servePage(out);
                return;
            }

            if (!path.startsWith("/video/")) {
                writeSimpleStatus(
                        out,
                        404,
                        "Not Found"
                );
                return;
            }

            String name =
                    path.substring("/video/".length());

            relayFromOrigin(
                    out,
                    originHost,
                    originPort,
                    name,
                    rangeHeader,
                    trustedServerKey,
                    proxyConfig
            );

        } catch (Exception e) {

            System.err.println(
                    "Proxy request failed: "
                            + e.getMessage()
            );
        }
    }

    static void servePage(OutputStream out)
            throws IOException {

        byte[] page = INDEX_HTML.getBytes(
                StandardCharsets.UTF_8
        );

        String headers =
                "HTTP/1.1 200 OK\r\n"
                        + "Content-Type: text/html; charset=utf-8\r\n"
                        + "Content-Length: " + page.length + "\r\n"
                        + "Connection: close\r\n\r\n";

        out.write(
                headers.getBytes(
                        StandardCharsets.US_ASCII
                )
        );

        out.write(page);
        out.flush();
    }

    static void relayFromOrigin(
            OutputStream browserOut,
            String originHost,
            int originPort,
            String name,
            String rangeHeader,
            PublicKey trustedServerKey,
            CryptoConfig proxyConfig) throws Exception {

        boolean responseStarted = false;

        try (Socket origin = new Socket()) {

            origin.connect(
                    new InetSocketAddress(
                            originHost,
                            originPort
                    ),
                    5000
            );

            origin.setSoTimeout(30000);

            try (SecureChannel channel =
                         SecureChannel.connect(
                                 origin,
                                 trustedServerKey,
                                 proxyConfig
                         )) {

                SecureHttpTransport transport =
                        new SecureHttpTransport(channel);

                StringBuilder request =
                        new StringBuilder();

                request.append("GET /media/")
                        .append(name)
                        .append(" HTTP/1.1\r\n");

                request.append("Host: ")
                        .append(originHost)
                        .append(":")
                        .append(originPort)
                        .append("\r\n");

                if (rangeHeader != null) {
                    request.append("Range: ")
                            .append(rangeHeader)
                            .append("\r\n");
                }

                request.append(
                        "Connection: close\r\n\r\n"
                );

                transport.sendHeaders(
                        request.toString()
                );

                transport.finishSending();

                String responseHeaders =
                        transport.receiveHeaders();

                String[] lines =
                        responseHeaders.split("\r\n");

                if (lines.length == 0
                        || !lines[0].startsWith("HTTP/1.1 ")) {

                    throw new IOException(
                            "Invalid Origin HTTP response"
                    );
                }

                String[] statusParts =
                        lines[0].split(" ", 3);

                if (statusParts.length < 3) {
                    throw new IOException(
                            "Invalid HTTP status line"
                    );
                }

                int statusCode =
                        Integer.parseInt(statusParts[1]);

                String reason = statusParts[2];

                long contentLength = -1;

                String contentType = null;
                String contentRange = null;
                String acceptRanges = null;

                for (int i = 1; i < lines.length; i++) {

                    int separator =
                            lines[i].indexOf(':');

                    if (separator <= 0) {
                        continue;
                    }

                    String headerName =
                            lines[i]
                                    .substring(0, separator)
                                    .trim()
                                    .toLowerCase();

                    String headerValue =
                            lines[i]
                                    .substring(separator + 1)
                                    .trim();

                    switch (headerName) {

                        case "content-length" ->
                                contentLength =
                                        Long.parseLong(
                                                headerValue
                                        );

                        case "content-type" ->
                                contentType = headerValue;

                        case "content-range" ->
                                contentRange = headerValue;

                        case "accept-ranges" ->
                                acceptRanges = headerValue;
                    }
                }

                if (contentLength < 0) {
                    throw new IOException(
                            "Missing or invalid Content-Length"
                    );
                }

                StringBuilder browserResponse =
                        new StringBuilder();

                browserResponse
                        .append("HTTP/1.1 ")
                        .append(statusCode)
                        .append(" ")
                        .append(reason)
                        .append("\r\n");

                if (contentType != null) {
                    browserResponse
                            .append("Content-Type: ")
                            .append(contentType)
                            .append("\r\n");
                }

                if (acceptRanges != null) {
                    browserResponse
                            .append("Accept-Ranges: ")
                            .append(acceptRanges)
                            .append("\r\n");
                }

                if (contentRange != null) {
                    browserResponse
                            .append("Content-Range: ")
                            .append(contentRange)
                            .append("\r\n");
                }

                browserResponse
                        .append("Content-Length: ")
                        .append(contentLength)
                        .append("\r\n");

                browserResponse.append(
                        "Connection: close\r\n\r\n"
                );

                // The Origin response is authenticated.
                // The browser connection itself remains HTTP.
                browserOut.write(
                        browserResponse.toString().getBytes(
                                StandardCharsets.US_ASCII
                        )
                );

                browserOut.flush();
                responseStarted = true;

                // Exclude the HTTP header records from media statistics.
                long initialReceivedBlocks = transport.getReceivedDataBlocks();
                long initialReceivedBytes = transport.getReceivedDataBytes();
                long forwardedBlocks = 0;
                long forwardedBytes = 0;
                long mediaStartNanos = System.nanoTime();

                long remaining = contentLength;

                while (remaining > 0) {

                    byte[] block =
                            transport.receiveData();

                    if (block == null) {
                        throw new IOException(
                                "Origin response truncated: "
                                        + remaining + " bytes missing"
                        );
                    }

                    if (block.length > remaining) {
                        throw new IOException(
                                "Origin sent more data than Content-Length"
                        );
                    }

                    browserOut.write(block);
                    browserOut.flush();

                    forwardedBlocks++;
                    forwardedBytes += block.length;
                    remaining -= block.length;
                }

                // Even after all bytes arrive, require
                // the authenticated END record.
                if (transport.receiveData() != null) {
                    throw new IOException(
                            "Unexpected data after HTTP body"
                    );
                }

                if (!transport.isReceiveFinished()) {
                    throw new IOException(
                            "Missing authenticated END"
                    );
                }

                long elapsedNanos = System.nanoTime() - mediaStartNanos;
                double elapsedSeconds = elapsedNanos / 1_000_000_000.0;
                double throughputKBs = elapsedSeconds > 0
                        ? forwardedBytes / 1000.0 / elapsedSeconds
                        : 0.0;

                long receivedBlocks = transport.getReceivedDataBlocks()
                        - initialReceivedBlocks;
                long receivedBytes = transport.getReceivedDataBytes()
                        - initialReceivedBytes;

                // Content-Range identifies the total original file size for
                // HTTP 206 responses, e.g. "bytes 0-1023/1720238".
                long originalFileSize = -1;
                if (contentRange != null) {
                    int slash = contentRange.lastIndexOf('/');
                    if (slash >= 0) {
                        try {
                            originalFileSize = Long.parseLong(
                                    contentRange.substring(slash + 1).trim()
                            );
                        } catch (NumberFormatException ignored) {
                            // Unknown total size; do not invent a comparison.
                        }
                    }
                } else if (statusCode == 200) {
                    originalFileSize = contentLength;
                }

                System.out.println("=== Secure streaming statistics ===");
                System.out.println("Media: " + name);
                System.out.println("HTTP status: " + statusCode);
                System.out.println("Encrypted DATA records received and authenticated: "
                        + receivedBlocks);
                System.out.println("Decrypted DATA blocks forwarded: " + forwardedBlocks);
                System.out.println("Authenticated media bytes received: " + receivedBytes);
                System.out.println("Media bytes forwarded: " + forwardedBytes);
                System.out.printf(java.util.Locale.ROOT,
                        "Media forwarding throughput: %.2f kB/s%n", throughputKBs);
                System.out.printf(java.util.Locale.ROOT,
                        "Media transfer duration: %.3f s%n", elapsedSeconds);
                if (originalFileSize >= 0) {
                    System.out.println("Original media file size: "
                            + originalFileSize + " bytes");
                    System.out.println("Transferred portion of original file: "
                            + forwardedBytes + "/" + originalFileSize + " bytes");
                } else {
                    System.out.println("Original media file size: unavailable");
                }
                System.out.println("Note: counts exclude HTTP headers and END; "
                        + "encrypted wire overhead is not included.");
                System.out.println("Secure Origin response completed: "
                        + contentLength + " bytes");
            }

        } catch (Exception e) {

            System.err.println(
                    "Secure Origin error: "
                            + e.getMessage()
            );

            // Once HTTP headers have been sent, the
            // response cannot be replaced with a 502.
            if (!responseStarted) {
                writeSimpleStatus(
                        browserOut,
                        502,
                        "Bad Gateway"
                );
            } else {
                throw e;
            }
        }
    }

    static void writeSimpleStatus(
            OutputStream out,
            int code,
            String reason) throws IOException {

        String response =
                "HTTP/1.1 " + code + " " + reason + "\r\n"
                        + "Content-Length: 0\r\n"
                        + "Connection: close\r\n\r\n";

        out.write(
                response.getBytes(
                        StandardCharsets.US_ASCII
                )
        );

        out.flush();
    }
}
