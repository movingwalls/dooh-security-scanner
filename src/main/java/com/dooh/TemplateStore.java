package com.dooh;

import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Makes the scanner work from a single jar: the DOOH templates are packaged inside it and are extracted into the
 * per-user cache folder. The extracted copy is verified against the jar on every run.
 */
final class TemplateStore {

    private static final String PREFIX = "templates/";

    private TemplateStore() {
    }

    /** Where the packaged templates for this scanner version are extracted. */
    static Path extractedDir() {
        return NucleiInstaller.cacheRoot().resolve("templates").resolve(DOOHSecurityScanner.VERSION);
    }

    /**
     * Makes the templates packaged in the running jar available on disk, and guarantees they are exactly the jar's.
     *
     * @return the template directory, or {@code null} when not running from a jar that contains them
     */
    static Path extractFromJar() throws IOException {
        Path jarPath;
        try {
            jarPath = Paths.get(DOOHSecurityScanner.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        } catch (URISyntaxException | RuntimeException e) {
            return null;
        }
        return extractFrom(jarPath, extractedDir());
    }

    /**
     * Test seam. The extracted copy in {@code target} is compared with the jar on every call (every file's SHA-256,
     * and no extra files); if anything differs, was added or is missing, it is deleted and extracted again.
     */
    static Path extractFrom(Path jarPath, Path target) throws IOException {
        if (!Files.isRegularFile(jarPath) || !jarPath.toString().endsWith(".jar")) {
            return null;
        }
        try (JarFile jar = new JarFile(jarPath.toFile())) {
            Map<String, String> expected = new TreeMap<>();
            for (Enumeration<JarEntry> en = jar.entries(); en.hasMoreElements(); ) {
                JarEntry e = en.nextElement();
                String name = e.getName();
                if (e.isDirectory() || !name.startsWith(PREFIX) || !name.endsWith(".yaml")) {
                    continue;
                }
                Path rel = Paths.get(name.substring(PREFIX.length())).normalize();
                if (rel.isAbsolute() || rel.startsWith("..") || rel.toString().isEmpty()) { // zip-slip guard
                    throw new IOException("Unsafe path in jar: " + name);
                }
                try (InputStream in = jar.getInputStream(e)) {
                    expected.put(rel.toString().replace('\\', '/'), sha256(in));
                }
            }
            if (expected.isEmpty()) {
                return null;
            }
            if (matches(target, expected)) {
                return target;
            }
            // normalised and absolute, so the zip-slip check below compares like with like even when the cache folder
            // was given with ".." or as a relative path (e.g. DOOH_SCANNER_HOME=../cache)
            Path staging = target.toAbsolutePath().normalize().resolveSibling(target.getFileName() + ".tmp");
            deleteTree(staging);
            for (String rel : expected.keySet()) {
                Path dest = staging.resolve(rel).normalize();
                if (!dest.startsWith(staging)) { // zip-slip guard
                    throw new IOException("Unsafe path in jar: " + rel);
                }
                Files.createDirectories(dest.getParent());
                try (InputStream in = jar.getInputStream(jar.getJarEntry(PREFIX + rel))) {
                    Files.copy(in, dest, StandardCopyOption.REPLACE_EXISTING);
                }
            }
            Files.writeString(staging.resolve(".complete"), "ok");
            deleteTree(target);
            Files.move(staging, target, StandardCopyOption.REPLACE_EXISTING);
            return target;
        }
    }

    /** True when {@code dir} holds exactly the expected files (relative path -> SHA-256) plus the marker. */
    private static boolean matches(Path dir, Map<String, String> expected) {
        if (!Files.isDirectory(dir) || !Files.exists(dir.resolve(".complete"))) {
            return false;
        }
        try (var walk = Files.walk(dir)) {
            Set<String> seen = new HashSet<>();
            for (Path f : (Iterable<Path>) walk.filter(Files::isRegularFile)::iterator) {
                String rel = dir.relativize(f).toString().replace('\\', '/');
                if (rel.equals(".complete")) {
                    continue;
                }
                String want = expected.get(rel);
                if (want == null) {
                    return false; // a file that is not in the jar
                }
                try (InputStream in = Files.newInputStream(f)) {
                    if (!want.equals(sha256(in))) {
                        return false; // changed
                    }
                }
                seen.add(rel);
            }
            return seen.size() == expected.size(); // nothing missing
        } catch (IOException e) {
            return false;
        }
    }

    private static String sha256(InputStream in) throws IOException {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                sha.update(buf, 0, n);
            }
            StringBuilder sb = new StringBuilder();
            for (byte x : sha.digest()) {
                sb.append(String.format("%02x", x));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IOException(e);
        }
    }

    private static void deleteTree(Path p) throws IOException {
        if (!Files.exists(p)) {
            return;
        }
        try (var walk = Files.walk(p)) {
            for (Path x : (Iterable<Path>) walk.sorted(java.util.Comparator.reverseOrder())::iterator) {
                Files.delete(x);
            }
        }
    }
}
