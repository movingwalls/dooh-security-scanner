package com.dooh;

import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Makes the scanner work from a single jar: the DOOH templates are packaged inside it and are
 * extracted once into the per-user cache folder when no {@code templates/} folder is found.
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
     * Extracts the templates packaged in the running jar.
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
        if (!Files.isRegularFile(jarPath) || !jarPath.toString().endsWith(".jar")) {
            return null;
        }
        Path target = extractedDir();
        Path marker = target.resolve(".complete");
        if (Files.exists(marker)) {
            return target;
        }
        Path staging = target.resolveSibling(target.getFileName() + ".tmp");
        deleteTree(staging);
        int count = 0;
        try (JarFile jar = new JarFile(jarPath.toFile())) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry e = entries.nextElement();
                String name = e.getName();
                if (e.isDirectory() || !name.startsWith(PREFIX) || !name.endsWith(".yaml")) {
                    continue;
                }
                Path dest = staging.resolve(name.substring(PREFIX.length())).normalize();
                if (!dest.startsWith(staging)) { // zip-slip guard
                    throw new IOException("Unsafe path in jar: " + name);
                }
                Files.createDirectories(dest.getParent());
                try (InputStream in = jar.getInputStream(e)) {
                    Files.copy(in, dest, StandardCopyOption.REPLACE_EXISTING);
                }
                count++;
            }
        }
        if (count == 0) {
            deleteTree(staging);
            return null;
        }
        Files.writeString(staging.resolve(".complete"), "ok");
        deleteTree(target);
        Files.move(staging, target, StandardCopyOption.REPLACE_EXISTING);
        return target;
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
