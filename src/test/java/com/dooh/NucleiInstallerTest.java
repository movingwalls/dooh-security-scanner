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
    private String checksumsFile = "";

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
            String path = ex.getRequestURI().getPath();
            if (path.equals("/latest")) {
                ex.getResponseHeaders().add("Location", "https://github.com/x/y/releases/tag/v9.8.7");
                ex.sendResponseHeaders(302, -1);
            } else if (path.equals("/latest-broken")) {
                ex.sendResponseHeaders(200, -1);
            } else if (path.endsWith("nuclei_9.8.7_checksums.txt")) {
                byte[] t = (checksumsFile).getBytes(StandardCharsets.UTF_8);
                ex.sendResponseHeaders(200, t.length);
                ex.getResponseBody().write(t);
            } else if (path.endsWith(NucleiInstaller.assetName("9.8.7", "linux_amd64"))
                    || path.endsWith(NucleiInstaller.assetName("linux_amd64"))) {
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
            assertEquals(2, s.count(), "only the executable and its recorded hash; no temp files left behind");
        }
        assertEquals(sha(Files.readAllBytes(dest)), Files.readString(NucleiInstaller.recordFor(dest)).trim());
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

    @Test
    void parsesChecksumFile() {
        String h = "a".repeat(64);
        String text = "bad  nuclei_1.0.0_linux_amd64.zip\n" + h + "  nuclei_1.0.0_linux_arm64.zip\n"
                + h.toUpperCase() + "  nuclei_1.0.0_macOS_arm64.zip\n";
        assertEquals(h, NucleiInstaller.parseChecksum(text, "nuclei_1.0.0_linux_arm64.zip"));
        assertEquals(h, NucleiInstaller.parseChecksum(text, "nuclei_1.0.0_macOS_arm64.zip"), "normalised to lower case");
        assertNull(NucleiInstaller.parseChecksum(text, "nuclei_1.0.0_linux_amd64.zip"), "malformed hash line ignored");
        assertNull(NucleiInstaller.parseChecksum(text, "nuclei_1.0.0_windows_amd64.zip"));
    }

    @Test
    void comparesAndExtractsVersions() {
        assertTrue(NucleiInstaller.compareVersions("3.11.1", "3.4.10") > 0, "numeric, not alphabetical");
        assertEquals(0, NucleiInstaller.compareVersions("3.4.10", "3.4.10"));
        assertTrue(NucleiInstaller.compareVersions("3.4.9", "3.4.10") < 0);
        assertEquals("3.11.1", NucleiInstaller.versionIn("[INF] Nuclei Engine Version: v3.11.1\n"));
        assertNull(NucleiInstaller.versionIn("nothing here"));
        assertTrue(NucleiInstaller.isPlainVersion("3.4.10"));
        assertFalse(NucleiInstaller.isPlainVersion("../../etc"));
        assertFalse(NucleiInstaller.isPlainVersion("3.4.10-beta"));
        assertFalse(NucleiInstaller.isPlainVersion(null));
    }

    @Test
    void resolvesLatestVersionFromRedirect() throws Exception {
        assertEquals("9.8.7", NucleiInstaller.resolveLatestVersion(base + "latest"));
        assertThrows(IOException.class, () -> NucleiInstaller.resolveLatestVersion(base + "latest-broken"));
        assertThrows(IOException.class, () -> NucleiInstaller.resolveLatestVersion("http://example.com/latest"));
    }

    @Test
    void installsLatestUsingTheReleasesOwnChecksum() throws Exception {
        checksumsFile = "ignored  other.zip\n" + sha(zip) + "  " + NucleiInstaller.assetName("9.8.7", "linux_amd64") + "\n";
        String version = NucleiInstaller.resolveLatestVersion(base + "latest");
        String hash = NucleiInstaller.fetchChecksum(base, version, "linux_amd64");
        Path dest = tmp.resolve("latest").resolve("nuclei");
        NucleiInstaller.install(base, version, "linux_amd64", Map.of("linux_amd64", hash), dest);
        assertEquals("#!/bin/sh\necho fake\n", Files.readString(dest));
    }

    @Test
    void latestWithWrongChecksumIsRejected() throws Exception {
        checksumsFile = "0".repeat(64) + "  " + NucleiInstaller.assetName("9.8.7", "linux_amd64") + "\n";
        String hash = NucleiInstaller.fetchChecksum(base, "9.8.7", "linux_amd64");
        Path dest = tmp.resolve("l2").resolve("nuclei");
        IOException ex = assertThrows(IOException.class,
                () -> NucleiInstaller.install(base, "9.8.7", "linux_amd64", Map.of("linux_amd64", hash), dest));
        assertTrue(ex.getMessage().contains("Checksum mismatch"));
        assertFalse(Files.exists(dest));
    }

    @Test
    void missingChecksumEntryFails() {
        checksumsFile = "";
        assertThrows(IOException.class, () -> NucleiInstaller.fetchChecksum(base, "9.8.7", "linux_amd64"));
    }

    @Test
    void rejectsUnsafeVersionStrings() {
        assertThrows(IOException.class, () -> NucleiInstaller.installVersion("../evil"));
    }

    @Test
    void rejectsExtractedExecutableThatIsNotTheOfficialBuild() throws Exception {
        Path dest = tmp.resolve("b5").resolve("nuclei");
        IOException ex = assertThrows(IOException.class, () -> NucleiInstaller.install(
                base, NucleiInstaller.VERSION, "linux_amd64", Map.of("linux_amd64", sha(zip)), dest, "0".repeat(64)));
        assertTrue(ex.getMessage().contains("does not match the official build"));
        assertFalse(Files.exists(dest), "nothing is kept");
    }

    @Test
    void everyPinnedArchiveHasAPinnedExecutableHash() {
        assertEquals(NucleiInstaller.SHA256.keySet(), NucleiInstaller.BINARY_SHA256.keySet());
        for (String h : NucleiInstaller.BINARY_SHA256.values()) {
            assertTrue(h.matches("[0-9a-f]{64}"));
        }
    }

    @Test
    void trustsOnlyOfficialBuildsOrRecordedCacheCopies() throws Exception {
        Path cache = tmp.resolve("cache").resolve("nuclei");
        Path official = Files.write(tmp.resolve("official"), "official build".getBytes(StandardCharsets.UTF_8));
        Map<String, String> pinned = Map.of("linux_amd64", NucleiInstaller.sha256(official));

        // planted file that is not the official build, even with a hash file beside it: not trusted outside the cache
        Path planted = Files.write(tmp.resolve("planted"), "evil".getBytes(StandardCharsets.UTF_8));
        Files.writeString(NucleiInstaller.recordFor(planted), NucleiInstaller.sha256(planted));
        assertFalse(NucleiInstaller.isTrusted(planted, "linux_amd64", pinned, cache));

        assertTrue(NucleiInstaller.isTrusted(official, "linux_amd64", pinned, cache), "the official build is trusted anywhere");
        assertFalse(NucleiInstaller.isTrusted(official, null, pinned, cache), "unknown platform: nothing is official");
        assertFalse(NucleiInstaller.isTrusted(tmp.resolve("missing"), "linux_amd64", pinned, cache));

        // a copy this scanner installed into its cache is trusted while its recorded hash matches...
        Path cached = Files.write(Files.createDirectories(cache.resolve("9.9.9")).resolve("nuclei"), "latest build".getBytes(StandardCharsets.UTF_8));
        Files.writeString(NucleiInstaller.recordFor(cached), NucleiInstaller.sha256(cached));
        assertTrue(NucleiInstaller.isTrusted(cached, "linux_amd64", pinned, cache));
        // ...and not once the file is tampered with
        Files.writeString(cached, "tampered");
        assertFalse(NucleiInstaller.isTrusted(cached, "linux_amd64", pinned, cache));
    }

    @Test
    void pathSearchSkipsRelativeEntriesAndTheCurrentFolder() throws Exception {
        String exe = NucleiInstaller.exeName();
        Path cwd = Files.createDirectories(tmp.resolve("work"));
        Path good = Files.createDirectories(tmp.resolve("good"));
        Files.writeString(cwd.resolve(exe), "x");
        Files.writeString(good.resolve(exe), "x");
        Files.writeString(Files.createDirectories(tmp.resolve("rel")).resolve(exe), "x");
        String sep = java.io.File.pathSeparator;
        String path = String.join(sep, "", ".", "rel", cwd.toString(), good.toString());
        assertEquals(java.util.List.of(good.resolve(exe)), NucleiInstaller.pathCandidates(path, cwd));
        assertTrue(NucleiInstaller.pathCandidates(null, cwd).isEmpty());
    }
}
