package com.dooh;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Runs the real scanner as a separate process and proves that a Nuclei planted where the user happens to be
 * (the working folder, a tampered cache entry, a relative PATH entry) is never executed.
 */
class PlantedBinaryTest {

    @TempDir
    Path tmp;

    /** A fake "nuclei" that answers -version and leaves a marker file if it is ever run. */
    private Path fakeNuclei(Path dir, Path marker) throws Exception {
        Files.createDirectories(dir);
        Path f = dir.resolve("nuclei");
        Files.writeString(f, "#!/bin/sh\necho ran > '" + marker + "'\necho 'Nuclei Engine Version: v3.4.10'\n", StandardCharsets.UTF_8);
        assertTrue(f.toFile().setExecutable(true));
        return f;
    }

    private int runScanner(Path workDir, Path home, String pathEnv, List<String> extra, StringBuilder out) throws Exception {
        List<String> cmd = new ArrayList<>(List.of(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-cp", System.getProperty("java.class.path"), "com.dooh.DOOHSecurityScanner",
                "-h", "127.0.0.1", "--yes", "--offline", "--out", tmp.resolve("scans").toString()));
        cmd.addAll(extra);
        ProcessBuilder pb = new ProcessBuilder(cmd).directory(workDir.toFile()).redirectErrorStream(true);
        pb.environment().put("DOOH_SCANNER_HOME", home.toString());
        pb.environment().put("PATH", pathEnv);
        Process p = pb.start();
        out.append(new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8));
        assertTrue(p.waitFor(120, TimeUnit.SECONDS));
        return p.exitValue();
    }

    @Test
    void neverRunsANucleiPlantedInTheWorkingFolderOrACachedCopyThatWasTamperedWith() throws Exception {
        assumeFalse(NucleiInstaller.isWindows(), "uses a shell-script stand-in for nuclei");
        Path work = Files.createDirectories(tmp.resolve("Downloads"));
        Path home = Files.createDirectories(tmp.resolve("home"));
        Path marker1 = tmp.resolve("ran-in-cwd");
        Path marker2 = tmp.resolve("ran-from-cache");
        Path marker3 = tmp.resolve("ran-from-relative-path");
        fakeNuclei(work, marker1);                                                              // planted in the folder the user ran from
        fakeNuclei(home.resolve("nuclei").resolve(NucleiInstaller.VERSION), marker2);           // tampered cache entry, no valid hash record
        fakeNuclei(work.resolve("bin"), marker3);                                               // reachable only via a relative PATH entry
        Files.createDirectories(work.resolve("templates")).resolve("evil.yaml").toFile().createNewFile();

        StringBuilder out = new StringBuilder();
        int code = runScanner(work, home, ".:bin:/usr/bin:/bin", List.of(), out);

        assertFalse(Files.exists(marker1), "working-folder nuclei was executed:\n" + out);
        assertFalse(Files.exists(marker2), "tampered cached nuclei was executed:\n" + out);
        assertFalse(Files.exists(marker3), "relative-PATH nuclei was executed:\n" + out);
        assertEquals(3, code, "with no trusted Nuclei and downloads forbidden the run must stop with an error:\n" + out);
        assertTrue(out.toString().contains("not the official Nuclei build"), out.toString());
    }

    @Test
    void anExplicitNucleiIsRunButWithAWarning() throws Exception {
        assumeFalse(NucleiInstaller.isWindows(), "uses a shell-script stand-in for nuclei");
        Path work = Files.createDirectories(tmp.resolve("w"));
        Path marker = tmp.resolve("ran-explicit");
        Path mine = fakeNuclei(tmp.resolve("mine"), marker);
        StringBuilder out = new StringBuilder();
        runScanner(work, Files.createDirectories(tmp.resolve("h")), "/usr/bin:/bin", List.of("--nuclei", mine.toString()), out);
        assertTrue(Files.exists(marker), "an explicitly chosen --nuclei is the user's decision and is used");
        assertTrue(out.toString().contains("not checked against the official build"), out.toString());
    }
}
