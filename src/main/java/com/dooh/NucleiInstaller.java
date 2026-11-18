package com.dooh;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Locale;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Downloads the pinned Nuclei release from ProjectDiscovery's official GitHub releases.
 *
 * <p>Supply-chain safety: the version is pinned, the expected SHA-256 of every supported platform
 * archive is compiled into this class (taken from the official {@code nuclei_<version>_checksums.txt}),
 * the archive is verified <em>before</em> anything is extracted, only the single Nuclei executable is
 * extracted, and downloads must use HTTPS. Nothing is executed here.
 */
final class NucleiInstaller {

    /** The Nuclei version this scanner is tested with. */
    static final String VERSION = "3.4.10";

    /** SHA-256 of each official release archive, from nuclei_3.4.10_checksums.txt. */
    static final Map<String, String> SHA256 = Map.of(
            "linux_amd64", "234c12cc5288af071abdcd6f854245b6067345556e1235cf96b76725c1004357",
            "linux_arm64", "d1ed1a5c0df49d8fcd64cab4ff5840b793d6bf133b082bb6a7f67d5fc0f9c327",
            "linux_386", "35fdf9077c6c4f3e448d473e7946964b36e9b4f91317ab2dd37a14b86509f037",
            "linux_arm", "e8d79f94076083f6b434092ae93cbc5e51f8e087c8aed21a7e086b8c1ca1a4ca",
            "macOS_amd64", "70aec7192de93428a65bc7f5d5c926dbf9c6ce6a0c3a724e5bd7c7ad672fec2b",
            "macOS_arm64", "e077705580bfa291cd237f3613e97d0057092fc8398e049bdd03344961119eb7",
            "windows_amd64", "7de765bdd73f1c8ec577e82df8196b3971ecd9efc7061a7cab931bc1a8055c68",
            "windows_386", "2a4cb6e8042437bb65c55c0d575951f9f6dcc3e31c88a5cfaa427c9af4c9e746");

    static final String OFFICIAL_BASE = "https://github.com/projectdiscovery/nuclei/releases/download/v" + VERSION + "/";

    /** Hard cap so a hostile or broken server cannot fill the disk. */
    private static final long MAX_ARCHIVE_BYTES = 200L * 1024 * 1024;

    private NucleiInstaller() {
    }

    /** Per-user folder for downloaded tools and extracted templates. */
    static Path cacheRoot() {
        String override = System.getenv("DOOH_SCANNER_HOME");
        if (override != null && !override.isBlank()) {
            return Paths.get(override);
        }
        return Paths.get(System.getProperty("user.home", "."), ".dooh-security-scanner");
    }

    static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    }

    static String exeName() {
        return isWindows() ? "nuclei.exe" : "nuclei";
    }

    /** Where the pinned Nuclei is (or will be) installed. */
    static Path installedBinary() {
        return cacheRoot().resolve("nuclei").resolve(VERSION).resolve(exeName());
    }

    /** Release asset key for this machine, e.g. {@code windows_amd64}; {@code null} if unsupported. */
    static String platformKey() {
        return platformKey(System.getProperty("os.name", ""), System.getProperty("os.arch", ""));
    }

    static String platformKey(String osName, String osArch) {
        String os = osName.toLowerCase(Locale.ROOT);
        String arch = osArch.toLowerCase(Locale.ROOT);
        String o;
        if (os.contains("win")) o = "windows";
        else if (os.contains("mac") || os.contains("darwin")) o = "macOS";
        else if (os.contains("linux")) o = "linux";
        else return null;
        String a;
        if (arch.equals("amd64") || arch.equals("x86_64")) a = "amd64";
        else if (arch.equals("aarch64") || arch.equals("arm64")) a = "arm64";
        else if (arch.equals("x86") || arch.equals("i386") || arch.equals("i686")) a = "386";
        else if (arch.startsWith("arm")) a = "arm";
        else return null;
        String key = o + "_" + a;
        return SHA256.containsKey(key) ? key : null;
    }

    static String assetName(String key) {
        return "nuclei_" + VERSION + "_" + key + ".zip";
    }

    /** Downloads, verifies and extracts the official release into {@link #installedBinary()}. */
    static Path install() throws IOException {
        String key = platformKey();
        if (key == null) {
            throw new IOException("No official Nuclei build is pinned for this system ("
                    + System.getProperty("os.name") + "/" + System.getProperty("os.arch")
                    + "). Install Nuclei " + VERSION + " manually and use --nuclei <path>.");
        }
        return install(OFFICIAL_BASE, key, SHA256, installedBinary());
    }

    /** Test seam: base URL, hash table and destination are parameters. */
    static Path install(String baseUrl, String key, Map<String, String> hashes, Path destination) throws IOException {
        String expected = hashes.get(key);
        if (expected == null) {
            throw new IOException("No checksum pinned for " + key);
        }
        URI uri = URI.create(baseUrl + assetName(key));
        boolean loopbackTest = "http".equals(uri.getScheme())
                && ("127.0.0.1".equals(uri.getHost()) || "localhost".equals(uri.getHost()));
        if (!"https".equals(uri.getScheme()) && !loopbackTest) {
            throw new IOException("Refusing to download over an insecure connection: " + uri);
        }

        Files.createDirectories(destination.getParent());
        Path archive = Files.createTempFile(destination.getParent(), "nuclei-", ".zip.part");
        Path tmpBinary = destination.resolveSibling(destination.getFileName() + ".part");
        try {
            String actual = download(uri, archive);
            if (!actual.equalsIgnoreCase(expected)) {
                throw new IOException("Checksum mismatch for " + assetName(key) + " (expected " + expected
                        + ", got " + actual + "). The download was discarded.");
            }
            extractBinary(archive, tmpBinary, destination.getFileName().toString());
            if (!isWindows()) {
                tmpBinary.toFile().setExecutable(true, false);
            }
            Files.move(tmpBinary, destination, StandardCopyOption.REPLACE_EXISTING);
            return destination;
        } finally {
            Files.deleteIfExists(archive);
            Files.deleteIfExists(tmpBinary);
        }
    }

    /** Streams the response to {@code target} and returns its SHA-256 (hex). */
    private static String download(URI uri, Path target) throws IOException {
        HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .connectTimeout(Duration.ofSeconds(20))
                .build();
        HttpRequest req = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofMinutes(5))
                .header("User-Agent", "dooh-security-scanner")
                .build();
        try {
            HttpResponse<InputStream> resp = client.send(req, HttpResponse.BodyHandlers.ofInputStream());
            if (resp.statusCode() != 200) {
                throw new IOException("Download failed: HTTP " + resp.statusCode() + " for " + uri);
            }
            if (!"https".equals(resp.uri().getScheme()) && !"127.0.0.1".equals(resp.uri().getHost())
                    && !"localhost".equals(resp.uri().getHost())) {
                throw new IOException("Download was redirected to an insecure address: " + resp.uri());
            }
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            long total = 0;
            try (InputStream in = resp.body(); var out = Files.newOutputStream(target)) {
                byte[] buf = new byte[64 * 1024];
                int n;
                while ((n = in.read(buf)) > 0) {
                    total += n;
                    if (total > MAX_ARCHIVE_BYTES) {
                        throw new IOException("Download is larger than expected; aborted.");
                    }
                    sha.update(buf, 0, n);
                    out.write(buf, 0, n);
                }
            }
            return hex(sha.digest());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Download interrupted", e);
        } catch (NoSuchAlgorithmException e) {
            throw new IOException(e);
        }
    }

    /** Copies only the entry whose file name equals {@code wanted}; everything else is ignored. */
    private static void extractBinary(Path archive, Path out, String wanted) throws IOException {
        try (ZipInputStream zin = new ZipInputStream(Files.newInputStream(archive))) {
            ZipEntry e;
            while ((e = zin.getNextEntry()) != null) {
                String name = e.getName();
                String base = name.substring(name.lastIndexOf('/') + 1);
                if (!e.isDirectory() && base.equals(wanted)) {
                    Files.copy(zin, out, StandardCopyOption.REPLACE_EXISTING);
                    return;
                }
            }
        }
        throw new IOException("The archive does not contain " + wanted);
    }

    static String sha256(Path file) throws IOException {
        try (InputStream in = Files.newInputStream(file)) {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = in.read(buf)) > 0) sha.update(buf, 0, n);
            return hex(sha.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IOException(e);
        }
    }

    private static String hex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02x", x));
        return s.toString();
    }
}
