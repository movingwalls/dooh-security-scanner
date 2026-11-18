package com.dooh;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class NucleiInstallerTest {

    @TempDir
    Path tmp;

    private HttpServer server;
    private byte[] zip;
    private String base;

    private static byte[] zipOf(String exeName, String content) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ZipOutputStream z = new ZipOutputStream(bos)) {
            z.putNextEntry(new ZipEntry("README.md"));
            z.write("readme".getBytes(StandardCharsets.UTF_8));
            z.closeEntry();
            z.putNextEntry(new ZipEntry(exeName));
            z.write(content.getBytes(StandardCharsets.UTF_8));
            z.closeEntry();
        }
        return bos.toByteArray();
    }

    @BeforeEach
    void start() throws IOException {
        zip = zipOf("nuclei", "#!/bin/sh\necho fake\n");
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", ex -> {
            if (ex.getRequestURI().getPath().endsWith(NucleiInstaller.assetName("linux_amd64"))) {
                ex.sendResponseHeaders(200, zip.length);
                ex.getResponseBody().write(zip);
            } else {
                ex.sendResponseHeaders(404, -1);
            }
            ex.close();
        });
        server.start();
        base = "http://127.0.0.1:" + server.getAddress().getPort() + "/";
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    private String sha(byte[] data) throws Exception {
        Path f = Files.write(tmp.resolve("x.bin"), data);
        return NucleiInstaller.sha256(f);
    }

    @Test
    void installsWhenChecksumMatches() throws Exception {
        Path dest = tmp.resolve("bin").resolve("nuclei");
        Path out = NucleiInstaller.install(base, "linux_amd64", Map.of("linux_amd64", sha(zip)), dest);
        assertEquals(dest, out);
        assertEquals("#!/bin/sh\necho fake\n", Files.readString(dest));
        assertFalse(Files.exists(tmp.resolve("bin").resolve("README.md")), "only the executable is extracted");
        try (var s = Files.list(tmp.resolve("bin"))) {
            assertEquals(1, s.count(), "no temp files left behind");
        }
    }

    @Test
    void rejectsChecksumMismatchAndKeepsNothing() throws Exception {
        Path dest = tmp.resolve("bin").resolve("nuclei");
        IOException ex = assertThrows(IOException.class,
                () -> NucleiInstaller.install(base, "linux_amd64", Map.of("linux_amd64", "0".repeat(64)), dest));
        assertTrue(ex.getMessage().contains("Checksum mismatch"));
        assertFalse(Files.exists(dest));
        try (var s = Files.list(tmp.resolve("bin"))) {
            assertEquals(0, s.count());
        }
    }

    @Test
    void failsOnHttpError() {
        Path dest = tmp.resolve("b2").resolve("nuclei");
        assertThrows(IOException.class,
                () -> NucleiInstaller.install(base, "windows_amd64", Map.of("windows_amd64", "a".repeat(64)), dest));
    }

    @Test
    void refusesInsecureNonLoopbackUrls() {
        Path dest = tmp.resolve("b3").resolve("nuclei");
        IOException ex = assertThrows(IOException.class, () -> NucleiInstaller.install(
                "http://example.com/", "linux_amd64", Map.of("linux_amd64", "a".repeat(64)), dest));
        assertTrue(ex.getMessage().contains("insecure"));
    }

    @Test
    void archiveWithoutExecutableIsRejected() throws Exception {
        zip = zipOf("something-else", "x");
        Path dest = tmp.resolve("b4").resolve("nuclei");
        assertThrows(IOException.class, () -> NucleiInstaller.install(base, "linux_amd64", Map.of("linux_amd64", sha(zip)), dest));
        assertFalse(Files.exists(dest));
    }

    @Test
    void platformDetection() {
        assertEquals("windows_amd64", NucleiInstaller.platformKey("Windows 11", "amd64"));
        assertEquals("linux_arm64", NucleiInstaller.platformKey("Linux", "aarch64"));
        assertEquals("macOS_arm64", NucleiInstaller.platformKey("Mac OS X", "aarch64"));
        assertEquals("macOS_amd64", NucleiInstaller.platformKey("Mac OS X", "x86_64"));
        assertNull(NucleiInstaller.platformKey("Solaris", "sparc"));
        assertNull(NucleiInstaller.platformKey("Windows 11", "aarch64"), "no pinned checksum for windows_arm64");
    }

    @Test
    void everySupportedPlatformHasAPinnedSha256() {
        assertFalse(NucleiInstaller.SHA256.isEmpty());
        for (var e : NucleiInstaller.SHA256.entrySet()) {
            assertTrue(e.getValue().matches("[0-9a-f]{64}"), e.getKey());
        }
        assertNotNull(NucleiInstaller.platformKey("Linux", "amd64"));
    }
}
