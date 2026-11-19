package com.dooh;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class TemplateStoreTest {

    @TempDir
    Path tmp;

    private Path jar(Map<String, String> entries) throws IOException {
        Path jar = tmp.resolve("scanner.jar");
        try (OutputStream o = Files.newOutputStream(jar); ZipOutputStream z = new ZipOutputStream(o)) {
            for (var e : entries.entrySet()) {
                z.putNextEntry(new ZipEntry(e.getKey()));
                z.write(e.getValue().getBytes(StandardCharsets.UTF_8));
                z.closeEntry();
            }
        }
        return jar;
    }

    @Test
    void extractsPackagedTemplates() throws Exception {
        Path jar = jar(Map.of("templates/a/one.yaml", "id: one", "templates/two.yaml", "id: two", "other.txt", "x"));
        Path target = tmp.resolve("cache").resolve("t");
        assertEquals(target, TemplateStore.extractFrom(jar, target));
        assertEquals("id: one", Files.readString(target.resolve("a/one.yaml")));
        assertEquals("id: two", Files.readString(target.resolve("two.yaml")));
        assertFalse(Files.exists(target.resolve("other.txt")));
    }

    @Test
    void restoresATamperedTemplate() throws Exception {
        Path jar = jar(Map.of("templates/one.yaml", "id: one"));
        Path target = tmp.resolve("t");
        TemplateStore.extractFrom(jar, target);
        Files.writeString(target.resolve("one.yaml"), "id: evil");
        TemplateStore.extractFrom(jar, target);
        assertEquals("id: one", Files.readString(target.resolve("one.yaml")));
    }

    @Test
    void removesAPlantedExtraFileAndRestoresADeletedOne() throws Exception {
        Path jar = jar(Map.of("templates/one.yaml", "id: one", "templates/two.yaml", "id: two"));
        Path target = tmp.resolve("t");
        TemplateStore.extractFrom(jar, target);
        Files.writeString(target.resolve("planted.yaml"), "id: planted");
        Files.delete(target.resolve("two.yaml"));
        TemplateStore.extractFrom(jar, target);
        assertFalse(Files.exists(target.resolve("planted.yaml")));
        assertTrue(Files.exists(target.resolve("two.yaml")));
    }

    @Test
    void leavesAnUntouchedCopyAlone() throws Exception {
        Path jar = jar(Map.of("templates/one.yaml", "id: one"));
        Path target = tmp.resolve("t");
        TemplateStore.extractFrom(jar, target);
        java.nio.file.attribute.FileTime old = java.nio.file.attribute.FileTime.fromMillis(1_000_000_000L);
        Files.setLastModifiedTime(target.resolve("one.yaml"), old);
        assertEquals(target, TemplateStore.extractFrom(jar, target));
        assertEquals(old, Files.getLastModifiedTime(target.resolve("one.yaml")), "an exact copy is reused, not rewritten");
    }

    @Test
    void anUnexpectedNonTemplateFileForcesACleanRestore() throws Exception {
        Path jar = jar(Map.of("templates/one.yaml", "id: one"));
        Path target = tmp.resolve("t");
        TemplateStore.extractFrom(jar, target);
        Files.writeString(target.resolve("note.txt"), "x");
        TemplateStore.extractFrom(jar, target);
        assertFalse(Files.exists(target.resolve("note.txt")));
    }

    @Test
    void refusesUnsafeEntryNamesAndEmptyJars() throws Exception {
        Path evil = jar(Map.of("templates/../../escape.yaml", "id: x"));
        assertThrows(IOException.class, () -> TemplateStore.extractFrom(evil, tmp.resolve("t1")));
        Path empty = jar(Map.of("readme.txt", "x"));
        assertNull(TemplateStore.extractFrom(empty, tmp.resolve("t2")));
        assertNull(TemplateStore.extractFrom(tmp.resolve("missing.jar"), tmp.resolve("t3")));
    }
}
