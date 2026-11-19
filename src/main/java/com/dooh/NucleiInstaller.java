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
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Downloads Nuclei from ProjectDiscovery's official GitHub releases, for the machine it runs on.
 *
 * <p>By default the tested version ({@link #VERSION}) is installed, checked against SHA-256 values compiled into
 * this class: first the archive (before anything is extracted), then the extracted executable. On request
 * ({@code --nuclei-version latest}) the latest release is installed instead: its version is read from the redirect
 * of {@code github.com/projectdiscovery/nuclei/releases/latest} and its SHA-256 from the checksums file published
 * with that release. That protects against corrupted or tampered downloads in transit, but not against a
 * compromised release, which is why it is opt-in.
 *
 * <p>Before the scanner runs any Nuclei it found by itself it calls {@link #isTrusted}: the executable must match
 * the compiled-in SHA-256 of the official build, or be a copy this scanner installed into its own cache and
 * recorded the hash of. HTTPS only, only the single executable is extracted, and version strings are validated
 * before they reach a URL or a path. Nothing is executed here.
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

    /** SHA-256 of the extracted Nuclei executable inside each archive above (nuclei / nuclei.exe). */
    static final Map<String, String> BINARY_SHA256 = Map.of(
            "linux_amd64", "794b5033f3e7b40b23bcf8a4e1c886d16275e0be2aaa19f0d8716a7bcb9e1489",
            "linux_arm64", "4db94b2dd84dbe1ab7a9e0939b93708c7ece9fc811a25dab8e2052e34f23f68c",
            "linux_386", "ae0d5b52e9e666c3c52c6d09ce1fc43d437958b9bccf0c0dacd377fb2ad047ce",
            "linux_arm", "dd644f1d8223641729b1b9dc71279696bf2d2bc8c8fcfa9f61bcba203cd093b0",
            "macOS_amd64", "bdd71dfe0aa66a38190a109f4828c739f1af2560bb2be3e528fb071e1adece2e",
            "macOS_arm64", "d5e6c57a0d0df4c598c9968dba497b945dc084e2ec7ee213995ee316f5081020",
            "windows_amd64", "91b64730daa83b29ba3a6d4e918b195ea7bc2da1f13132bb8d7cb33a8d691f4a",
            "windows_386", "f44da79e0fd5f310536afe6383aa4c224cd845096e0644368427dd13151eba86");

    static final String OFFICIAL_BASE = releaseBase(VERSION);

    /** Redirects to {@code .../releases/tag/v<latest>}; unlike the REST API it has no rate limit. */
    static final String LATEST_URL = "https://github.com/projectdiscovery/nuclei/releases/latest";

    private static final Pattern PLAIN_VERSION = Pattern.compile("\\d+\\.\\d+\\.\\d+");

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

    static String releaseBase(String version) {
        return "https://github.com/projectdiscovery/nuclei/releases/download/v" + version + "/";
    }

    static boolean isPlainVersion(String v) {
        return v != null && PLAIN_VERSION.matcher(v).matches();
    }

    /** Where the tested Nuclei is (or will be) installed. */
    static Path installedBinary() {
        return installedBinary(VERSION);
    }

    static Path installedBinary(String version) {
        return cacheRoot().resolve("nuclei").resolve(version).resolve(exeName());
    }

    /** Orders dotted numeric versions: negative, zero or positive like {@link Comparable}. */
    static int compareVersions(String a, String b) {
        String[] x = a.split("\\."), y = b.split("\\.");
        for (int i = 0; i < Math.max(x.length, y.length); i++) {
            int p = i < x.length ? Integer.parseInt(x[i]) : 0;
            int q = i < y.length ? Integer.parseInt(y[i]) : 0;
            if (p != q) return Integer.compare(p, q);
        }
        return 0;
    }

    /** Every Nuclei installed in the per-user cache by this scanner, highest version first. */
    static java.util.List<Path> installedBinaries() {
        Path dir = cacheRoot().resolve("nuclei");
        if (!Files.isDirectory(dir)) {
            return java.util.List.of();
        }
        try (Stream<Path> s = Files.list(dir)) {
            return s.filter(d -> isPlainVersion(d.getFileName().toString()))
                    .sorted((a, b) -> compareVersions(b.getFileName().toString(), a.getFileName().toString()))
                    .map(d -> d.resolve(exeName()))
                    .filter(Files::isRegularFile)
                    .collect(java.util.stream.Collectors.toList());
        } catch (IOException e) {
            return java.util.List.of();
        }
    }

    /** Where the hash recorded at install time lives for {@code exe}. */
    static Path recordFor(Path exe) {
        return exe.resolveSibling(exe.getFileName() + ".sha256");
    }

    /**
     * Whether the scanner may run this Nuclei without being told to. True only if the executable is byte-for-byte
     * the official build whose SHA-256 is compiled into this class, or a copy this scanner installed into its own
     * cache folder whose recorded hash still matches. A file merely sitting in the working folder, in Downloads or
     * next to the jar is never trusted by name.
     */
    static boolean isTrusted(Path exe) {
        return isTrusted(exe, platformKey(), BINARY_SHA256, cacheRoot().resolve("nuclei"));
    }

    static boolean isTrusted(Path exe, String key, Map<String, String> official, Path cacheNucleiDir) {
        try {
            if (!Files.isRegularFile(exe)) {
                return false;
            }
            String actual = sha256(exe);
            if (key != null && actual.equalsIgnoreCase(official.get(key))) {
                return true;
            }
            Path record = recordFor(exe);
            boolean inCache = exe.toAbsolutePath().normalize().startsWith(cacheNucleiDir.toAbsolutePath().normalize());
            return inCache && Files.isRegularFile(record) && Files.readString(record).trim().equalsIgnoreCase(actual);
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Nuclei executables found on {@code pathEnv}. Relative and empty entries (which mean "the current folder")
     * and the current folder itself are skipped, so a planted file in the folder the user ran from is never found.
     */
    static java.util.List<Path> pathCandidates(String pathEnv, Path cwd) {
        java.util.List<Path> found = new java.util.ArrayList<>();
        if (pathEnv == null) {
            return found;
        }
        Path here = cwd.toAbsolutePath().normalize();
        for (String entry : pathEnv.split(java.io.File.pathSeparator)) {
            if (entry.isBlank()) {
                continue;
            }
            Path dir;
            try {
                dir = Paths.get(entry.strip());
            } catch (RuntimeException e) {
                continue;
            }
            if (!dir.isAbsolute() || dir.normalize().equals(here)) {
                continue;
            }
            Path candidate = dir.resolve(exeName());
            if (Files.isRegularFile(candidate)) {
                found.add(candidate);
            }
        }
        return found;
    }

    /** Extracts {@code 3.11.1} from text such as {@code Nuclei Engine Version: v3.11.1}; {@code null} if absent. */
    static String versionIn(String text) {
        if (text == null) return null;
        Matcher m = Pattern.compile("v(\\d+\\.\\d+\\.\\d+)").matcher(text);
        return m.find() ? m.group(1) : null;
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
        return assetName(VERSION, key);
    }

    static String assetName(String version, String key) {
        return "nuclei_" + version + "_" + key + ".zip";
    }

    private static IOException unsupported() {
        return new IOException("No official Nuclei build is available for this system ("
                + System.getProperty("os.name") + "/" + System.getProperty("os.arch")
                + "). Install Nuclei manually and use --nuclei <path>.");
    }

    /** Installs the tested version ({@link #VERSION}) using the checksums compiled into this class. */
    static Path install() throws IOException {
        String key = platformKey();
        if (key == null) {
            throw unsupported();
        }
        return install(OFFICIAL_BASE, VERSION, key, SHA256, installedBinary(), BINARY_SHA256.get(key));
    }

    /**
     * Installs the latest official release for this machine. If the latest version or its checksum cannot be
     * looked up, falls back to the tested version so a flaky lookup never leaves the user without Nuclei.
     */
    static Path installLatest() throws IOException {
        String latest;
        try {
            latest = resolveLatestVersion(LATEST_URL);
        } catch (IOException e) {
            System.err.println("Could not look up the latest Nuclei (" + e.getMessage() + "); using " + VERSION + " instead.");
            return install();
        }
        return installVersion(latest);
    }

    /** Installs a specific release. The tested version uses the compiled-in checksum; others use the release's own. */
    static Path installVersion(String version) throws IOException {
        if (!isPlainVersion(version)) {
            throw new IOException("Not a valid Nuclei version: " + version);
        }
        if (version.equals(VERSION)) {
            return install();
        }
        String key = platformKey();
        if (key == null) {
            throw unsupported();
        }
        String base = releaseBase(version);
        String hash = fetchChecksum(base, version, key);
        return install(base, version, key, Map.of(key, hash), installedBinary(version));
    }

    /** Reads the latest version from the redirect of {@code latestUrl}; the redirect is never followed. */
    static String resolveLatestVersion(String latestUrl) throws IOException {
        for (int attempt = 1; ; attempt++) {
            try {
                return resolveLatestVersionOnce(latestUrl);
            } catch (IOException e) {
                if (!transientFailure(e) || attempt >= ATTEMPTS) {
                    throw e;
                }
                backoff(attempt);
            }
        }
    }

    private static String resolveLatestVersionOnce(String latestUrl) throws IOException {
        URI uri = URI.create(latestUrl);
        requireSecure(uri);
        HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(20))
                .build();
        HttpRequest req = HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(30))
                .header("User-Agent", "dooh-security-scanner").GET().build();
        try {
            HttpResponse<Void> resp = client.send(req, HttpResponse.BodyHandlers.discarding());
            String location = resp.headers().firstValue("Location").orElse("");
            Matcher m = Pattern.compile("/tag/v(\\d+\\.\\d+\\.\\d+)$").matcher(location);
            if (resp.statusCode() / 100 != 3 || !m.find()) {
                throw new IOException("unexpected answer (HTTP " + resp.statusCode() + ") from " + uri);
            }
            return m.group(1);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("lookup interrupted", e);
        }
    }

    /** Downloads {@code nuclei_<version>_checksums.txt} from the release and returns the hash for {@code key}. */
    static String fetchChecksum(String baseUrl, String version, String key) throws IOException {
        URI uri = URI.create(baseUrl + "nuclei_" + version + "_checksums.txt");
        requireSecure(uri);
        Path tmp = Files.createTempFile("nuclei-checksums-", ".txt");
        try {
            download(uri, tmp);
            String hash = parseChecksum(Files.readString(tmp), assetName(version, key));
            if (hash == null) {
                throw new IOException("no checksum for " + assetName(version, key) + " in the release's checksums file");
            }
            return hash;
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    /** Finds {@code <hash>  <asset>} in a {@code sha256sum}-style file; {@code null} if the asset is not listed. */
    static String parseChecksum(String text, String asset) {
        for (String line : text.split("\\R")) {
            String[] parts = line.trim().split("\\s+");
            if (parts.length == 2 && parts[1].equals(asset) && parts[0].matches("[0-9a-fA-F]{64}")) {
                return parts[0].toLowerCase(Locale.ROOT);
            }
        }
        return null;
    }

    private static void requireSecure(URI uri) throws IOException {
        boolean loopbackTest = "http".equals(uri.getScheme())
                && ("127.0.0.1".equals(uri.getHost()) || "localhost".equals(uri.getHost()));
        if (!"https".equals(uri.getScheme()) && !loopbackTest) {
            throw new IOException("Refusing to download over an insecure connection: " + uri);
        }
    }

    /** Test seam for the tested version: base URL, hash table and destination are parameters. */
    static Path install(String baseUrl, String key, Map<String, String> hashes, Path destination) throws IOException {
        return install(baseUrl, VERSION, key, hashes, destination, null);
    }

    static Path install(String baseUrl, String version, String key, Map<String, String> hashes, Path destination)
            throws IOException {
        return install(baseUrl, version, key, hashes, destination, null);
    }

    /** {@code expectedExeSha256}, when not null, is also checked against the extracted executable. */
    static Path install(String baseUrl, String version, String key, Map<String, String> hashes, Path destination,
                        String expectedExeSha256) throws IOException {
        String expected = hashes.get(key);
        if (expected == null) {
            throw new IOException("No checksum pinned for " + key);
        }
        URI uri = URI.create(baseUrl + assetName(version, key));
        requireSecure(uri);

        Files.createDirectories(destination.getParent());
        Path archive = Files.createTempFile(destination.getParent(), "nuclei-", ".zip.part");
        Path tmpBinary = destination.resolveSibling(destination.getFileName() + ".part");
        try {
            String actual = download(uri, archive);
            if (!actual.equalsIgnoreCase(expected)) {
                throw new IOException("Checksum mismatch for " + assetName(version, key) + " (expected " + expected
                        + ", got " + actual + "). The download was discarded.");
            }
            extractBinary(archive, tmpBinary, destination.getFileName().toString());
            String exeSha = sha256(tmpBinary);
            if (expectedExeSha256 != null && !exeSha.equalsIgnoreCase(expectedExeSha256)) {
                throw new IOException("The extracted Nuclei executable does not match the official build (expected "
                        + expectedExeSha256 + ", got " + exeSha + "). It was discarded.");
            }
            if (!isWindows()) {
                tmpBinary.toFile().setExecutable(true, false);
            }
            Files.move(tmpBinary, destination, StandardCopyOption.REPLACE_EXISTING);
            Files.writeString(recordFor(destination), exeSha + System.lineSeparator()); // checked again on every run
            return destination;
        } finally {
            Files.deleteIfExists(archive);
            Files.deleteIfExists(tmpBinary);
        }
    }

    /** Attempts for a network step that failed to connect or timed out (flaky Wi-Fi, busy CDN node). */
    private static final int ATTEMPTS = 3;

    private static boolean transientFailure(IOException e) {
        return e instanceof java.net.http.HttpTimeoutException || e instanceof java.net.ConnectException;
    }

    private static void backoff(int attempt) throws IOException {
        try {
            Thread.sleep(1000L * attempt);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new IOException("Download interrupted", ie);
        }
    }

    /** Streams the response to {@code target} and returns its SHA-256 (hex); retries connect failures and timeouts. */
    private static String download(URI uri, Path target) throws IOException {
        for (int attempt = 1; ; attempt++) {
            try {
                return downloadOnce(uri, target);
            } catch (IOException e) {
                if (!transientFailure(e) || attempt >= ATTEMPTS) {
                    throw e;
                }
                backoff(attempt);
            }
        }
    }

    private static String downloadOnce(URI uri, Path target) throws IOException {
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
