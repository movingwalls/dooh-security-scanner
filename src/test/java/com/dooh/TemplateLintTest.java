package com.dooh;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * Cheap static checks that catch the template mistakes found in the first review. They do not
 * replace {@code nuclei -validate}, which CI also runs.
 */
class TemplateLintTest {

    private static List<Path> templates() throws IOException {
        try (Stream<Path> s = Files.walk(Paths.get("templates"))) {
            return s.filter(p -> p.toString().endsWith(".yaml")).sorted().collect(Collectors.toList());
        }
    }

    @Test
    void thereAreTemplates() throws IOException {
        assertTrue(templates().size() >= 20);
    }

    @Test
    void everyTemplateLooksComplete() throws IOException {
        Set<String> ids = new HashSet<>();
        for (Path p : templates()) {
            String t = Files.readString(p);
            String name = p.toString();
            Matcher id = Pattern.compile("(?m)^id:\\s*(\\S+)\\s*$").matcher(t);
            assertTrue(id.find(), name + ": missing id");
            assertTrue(ids.add(id.group(1)), name + ": duplicate id " + id.group(1));
            assertTrue(t.endsWith("\n"), name + ": file looks truncated (no trailing newline)");
            assertTrue(t.contains("remediation:"), name + ": missing info.remediation");
            assertTrue(Pattern.compile("(?m)^\\s+author:\\s*(.+)$").matcher(t).find(), name + ": missing author");
            assertFalse(t.contains("security-researcher") || t.contains("security-compromised")
                    || t.contains("security-user") || t.contains("author: custom"), name + ": placeholder author");
            assertFalse(Pattern.compile("(?m)^\\s*-?\\s*status:\\s*[A-Za-z]").matcher(t).find(),
                    name + ": status matcher must be numeric, not a word like 'success'");
            assertFalse(Pattern.compile("(?m)^\\s*port:\\s*\\d+\\s*,\\s+\\d").matcher(t).find(),
                    name + ": port list must not contain spaces ('22,2222')");
            assertFalse(Pattern.compile("(?m)^network:").matcher(t).find(), name + ": use 'tcp:' (network: is deprecated)");
        }
    }

    @Test
    void loginTemplatesAreIntrusiveOnly() throws IOException {
        for (Path p : templates()) {
            String t = Files.readString(p);
            boolean sendsCredentials = t.contains("payloads:") || t.contains("password");
            if (sendsCredentials && t.contains("body:")) {
                assertTrue(Pattern.compile("(?m)^\\s*tags:.*\\bintrusive\\b").matcher(t).find(),
                        p + ": credential-sending templates must be tagged 'intrusive'");
            }
        }
    }

    @Test
    void noBareSuccessOrSnMatchers() throws IOException {
        String login = Files.readString(Paths.get("templates/led-controllers/novastar-default-login.yaml"));
        assertFalse(Pattern.compile("(?m)^\\s*-\\s*\"success\"\\s*$").matcher(login).find());
        String cfg = Files.readString(Paths.get("templates/led-controllers/novastar-config-exposure.yaml"));
        assertFalse(Pattern.compile("(?m)^\\s*-\\s*\"sn\"\\s*$").matcher(cfg).find());
    }

    @Test
    void adbHandshakeIsWellFormed() throws IOException {
        // CNXN header: command, arg0, arg1, data_length, data_crc32 (byte sum), magic = ~command
        String hex = "434e584e00000001001000000700000032020000bcb1a7b1686f73743a3a00";
        for (String f : List.of("templates/android/adb-unauthenticated-access.yaml", "templates/android/exposed-adb-detection.yaml")) {
            assertTrue(Files.readString(Paths.get(f)).contains(hex), f + ": ADB CNXN payload changed");
        }
        byte[] b = new byte[hex.length() / 2];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        int payloadLen = b.length - 24;
        assertEquals(7, payloadLen);
        int sum = 0;
        for (int i = 24; i < b.length; i++) sum += b[i] & 0xFF;
        assertEquals(sum, (b[16] & 0xFF) | (b[17] & 0xFF) << 8 | (b[18] & 0xFF) << 16 | (b[19] & 0xFF) << 24, "data checksum");
        for (int i = 0; i < 4; i++) {
            assertEquals((byte) ~b[i], b[20 + i], "magic = ~command");
        }
        assertEquals(payloadLen, b[12] & 0xFF);
    }
}
