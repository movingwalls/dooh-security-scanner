package com.dooh;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class DOOHReportPrinterTest {

    private static final String ADB =
            "{\"template-id\":\"dooh-adb-unauthenticated-access\",\"info\":{\"name\":\"ADB Unauthenticated\","
                    + "\"severity\":\"critical\",\"remediation\":\"Disable ADB\\n over network.\"},"
                    + "\"type\":\"tcp\",\"host\":\"203.0.113.11\",\"matched-at\":\"203.0.113.11:5555\"}";
    private static final String PANEL =
            "{\"template-id\":\"dooh-novastar-taurus-http\",\"info\":{\"name\":\"NovaStar Taurus portal\","
                    + "\"severity\":\"info\",\"remediation\":\"Keep it off the internet.\"},"
                    + "\"type\":\"http\",\"host\":\"203.0.113.12\",\"matched-at\":\"http://203.0.113.12:80/\","
                    + "\"extracted-results\":[\"NovaStar\"]}";

    @TempDir
    Path tmp;

    private DOOHReportPrinter.Report report(String... lines) throws IOException {
        Path f = tmp.resolve("results.jsonl");
        Files.write(f, List.of(lines));
        return DOOHReportPrinter.build(List.of("203.0.113.10", "203.0.113.11", "203.0.113.12"), f, false);
    }

    @Test
    void classifiesPassReviewFail() throws IOException {
        DOOHReportPrinter.Report r = report(ADB, PANEL);
        assertEquals(DOOHReportPrinter.Status.PASS, r.hosts.get(0).status());
        assertEquals(DOOHReportPrinter.Status.FAIL, r.hosts.get(1).status());
        assertEquals(DOOHReportPrinter.Status.REVIEW, r.hosts.get(2).status());
        assertEquals(1, r.count(DOOHReportPrinter.Status.PASS));
    }

    @Test
    void textReportKeepsEvidenceAndFix() throws IOException {
        String text = DOOHReportPrinter.renderText(report(ADB, PANEL));
        assertTrue(text.contains("[PASS]"));
        assertTrue(text.contains("[FAIL]"));
        assertTrue(text.contains("[REVIEW]"));
        assertTrue(text.contains("Evidence: 203.0.113.11:5555"));
        assertTrue(text.contains("-> NovaStar"));
        assertTrue(text.contains("Fix: Disable ADB over network."));
        assertTrue(text.contains("1 Passed | 1 Review | 1 Failed"));
        assertFalse(text.toLowerCase().contains("close inbound wan ports"), "no blanket WAN advice");
    }

    @Test
    void emptyResultsMeansEveryHostPasses() throws IOException {
        DOOHReportPrinter.Report r = report();
        assertEquals(3, r.count(DOOHReportPrinter.Status.PASS));
    }

    @Test
    void duplicatesAndGarbageLinesAreHandled() throws IOException {
        DOOHReportPrinter.Report r = report(ADB, ADB, "not json at all");
        assertEquals(1, r.hosts.get(1).findings.size());
        assertEquals(1, r.warnings.size());
    }

    @Test
    void jsonReportIsParseable() throws IOException {
        Object parsed = Json.parse(DOOHReportPrinter.renderJson(report(ADB, PANEL)));
        assertEquals(3, Json.asList(Json.asMap(parsed).get("hosts")).size());
    }

    @Test
    void htmlReportEscapesUntrustedEvidence() throws IOException {
        String evil = "{\"template-id\":\"x\",\"info\":{\"name\":\"<b>n</b>\",\"severity\":\"info\"},\"host\":\"203.0.113.12\","
                + "\"matched-at\":\"203.0.113.12:80\",\"extracted-results\":[\"<script>alert(1)</script>\"]}";
        String html = DOOHReportPrinter.renderHtml(report(evil));
        assertFalse(html.contains("<script>alert"), html);
        assertTrue(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assertTrue(html.contains("&lt;b&gt;n&lt;/b&gt;"));
        assertTrue(html.contains("Content-Security-Policy"));
    }

    @Test
    void hostOfStripsSchemePortAndPath() {
        assertEquals("1.2.3.4", DOOHReportPrinter.hostOf("http://1.2.3.4:8000/x"));
        assertEquals("1.2.3.4", DOOHReportPrinter.hostOf("1.2.3.4:5555"));
        assertEquals("example.com", DOOHReportPrinter.hostOf("HTTPS://Example.com/"));
    }
}
