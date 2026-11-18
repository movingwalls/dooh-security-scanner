package com.dooh;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Turns Nuclei's JSONL output into a PASS / REVIEW / FAIL report.
 *
 * <ul>
 *   <li><b>FAIL</b> - at least one medium, high or critical finding.</li>
 *   <li><b>REVIEW</b> - only info/low findings, e.g. a management panel or service is reachable
 *       and should be checked by a person.</li>
 *   <li><b>PASS</b> - no finding for that target.</li>
 * </ul>
 *
 * <p>This class never decides PASS for a scan that did not complete: the caller reports an ERROR
 * instead and does not render host results at all.
 */
public class DOOHReportPrinter {

    enum Status { PASS, REVIEW, FAIL }

    static final class Finding {
        final String templateId;
        final String name;
        final String severity;
        final String matchedAt;
        final String matcher;
        final List<String> extracted;
        final String remediation;

        Finding(String templateId, String name, String severity, String matchedAt, String matcher,
                List<String> extracted, String remediation) {
            this.templateId = templateId;
            this.name = name;
            this.severity = severity;
            this.matchedAt = matchedAt;
            this.matcher = matcher;
            this.extracted = extracted;
            this.remediation = remediation;
        }

        int rank() {
            return severityRank(severity);
        }
    }

    static final class HostResult {
        final String target;
        final List<Finding> findings = new ArrayList<>();

        HostResult(String target) {
            this.target = target;
        }

        Status status() {
            int top = findings.stream().mapToInt(Finding::rank).max().orElse(-1);
            if (top < 0) return Status.PASS;
            return top >= severityRank("medium") ? Status.FAIL : Status.REVIEW;
        }
    }

    static final class Report {
        final List<HostResult> hosts = new ArrayList<>();
        final List<String> warnings = new ArrayList<>();
        boolean intrusive;

        long count(Status s) {
            return hosts.stream().filter(h -> h.status() == s).count();
        }
    }

    static int severityRank(String sev) {
        switch (sev == null ? "" : sev.toLowerCase(Locale.ROOT)) {
            case "critical": return 4;
            case "high": return 3;
            case "medium": return 2;
            case "low": return 1;
            default: return 0;
        }
    }

    /** Reads Nuclei JSONL output and groups findings by target. */
    static Report build(List<String> targets, Path resultsFile, boolean intrusive) throws IOException {
        Report report = new Report();
        report.intrusive = intrusive;
        Map<String, HostResult> byTarget = new LinkedHashMap<>();
        for (String t : targets) {
            byTarget.put(t.toLowerCase(Locale.ROOT), new HostResult(t));
        }
        Set<String> seen = new LinkedHashSet<>();
        int badLines = 0;
        if (Files.exists(resultsFile)) {
            for (String line : Files.readAllLines(resultsFile, StandardCharsets.UTF_8)) {
                if (line.isBlank()) continue;
                Map<String, Object> ev;
                try {
                    ev = Json.asMap(Json.parse(line));
                } catch (RuntimeException ex) {
                    badLines++;
                    continue;
                }
                Map<String, Object> info = Json.asMap(ev.get("info"));
                String id = Json.str(ev.get("template-id"));
                String matchedAt = Json.str(ev.get("matched-at"));
                String host = hostOf(Json.str(ev.get("host")));
                if (!byTarget.containsKey(host)) {
                    String ip = hostOf(Json.str(ev.get("ip")));
                    host = byTarget.containsKey(ip) ? ip : host;
                }
                HostResult hr = byTarget.get(host);
                if (hr == null) { // finding for a host that was not in the list (e.g. redirect)
                    hr = new HostResult(host.isEmpty() ? "(unknown)" : host);
                    byTarget.put(host, hr);
                }
                if (!seen.add(host + "|" + id + "|" + matchedAt)) continue;
                List<String> extracted = new ArrayList<>();
                for (Object o : Json.asList(ev.get("extracted-results"))) extracted.add(Json.str(o));
                hr.findings.add(new Finding(
                        id,
                        Json.str(info.get("name")),
                        Json.str(info.get("severity")),
                        matchedAt,
                        Json.str(ev.get("matcher-name")),
                        extracted,
                        collapse(Json.str(info.get("remediation")))));
            }
        }
        if (badLines > 0) {
            report.warnings.add(badLines + " line(s) of the Nuclei output could not be read and were skipped.");
        }
        for (HostResult hr : byTarget.values()) {
            hr.findings.sort(Comparator.comparingInt(Finding::rank).reversed().thenComparing(f -> f.templateId));
            report.hosts.add(hr);
        }
        return report;
    }

    /** Strips scheme, path and port: "http://1.2.3.4:80/x" -> "1.2.3.4". */
    static String hostOf(String s) {
        String h = s.strip().toLowerCase(Locale.ROOT);
        int scheme = h.indexOf("://");
        if (scheme >= 0) h = h.substring(scheme + 3);
        int slash = h.indexOf('/');
        if (slash >= 0) h = h.substring(0, slash);
        int colon = h.lastIndexOf(':');
        if (colon >= 0 && h.indexOf(':') == colon) h = h.substring(0, colon);
        return h;
    }

    private static String collapse(String s) {
        return s.replaceAll("\\s+", " ").strip();
    }

    static String renderText(Report r) {
        String bar = "=".repeat(60);
        StringBuilder b = new StringBuilder();
        b.append(bar).append('\n').append("        DOOH PERIMETER DIAGNOSTIC AUDIT\n").append(bar).append('\n');
        for (HostResult h : r.hosts) {
            Status s = h.status();
            if (s == Status.PASS) {
                b.append(String.format("[PASS]   %s  -  No exposed DOOH management interfaces found%n", h.target));
                continue;
            }
            b.append(String.format("%-8s %s  -  %d finding(s), highest: %s%n", "[" + s + "]",
                    h.target, h.findings.size(), h.findings.get(0).severity.toUpperCase(Locale.ROOT)));
            for (Finding f : h.findings) {
                b.append(String.format("           - %s: %s%n", f.severity.toUpperCase(Locale.ROOT), f.name));
                StringBuilder ev = new StringBuilder(f.matchedAt);
                if (!f.matcher.isEmpty()) ev.append(" (matcher: ").append(f.matcher).append(')');
                if (!f.extracted.isEmpty()) ev.append(" -> ").append(String.join(", ", f.extracted));
                b.append("             Evidence: ").append(ev).append('\n');
                if (!f.remediation.isEmpty()) b.append("             Fix: ").append(f.remediation).append('\n');
            }
        }
        b.append(bar).append('\n');
        b.append(String.format("Result: %d Passed | %d Review | %d Failed (of %d)%n",
                r.count(Status.PASS), r.count(Status.REVIEW), r.count(Status.FAIL), r.hosts.size()));
        for (String w : r.warnings) b.append("Warning: ").append(w).append('\n');
        b.append(r.intrusive
                ? "Mode: INTRUSIVE (default-credential checks were enabled)\n"
                : "Mode: detection only (default-credential checks were NOT run; use --intrusive with the owner's consent)\n");
        b.append("Note: a finding means the service answered from where you scanned. If you scanned from inside the\n")
                .append("local network this does not by itself prove it is reachable from the internet; check your\n")
                .append("router/firewall port-forwards. PASS means none of this tool's checks matched, not that the\n")
                .append("device is secure.\n").append(bar).append('\n');
        return b.toString();
    }

    static String renderJson(Report r) {
        StringBuilder b = new StringBuilder("{\n");
        b.append("  \"mode\": ").append(Json.quote(r.intrusive ? "intrusive" : "detection-only")).append(",\n");
        b.append("  \"passed\": ").append(r.count(Status.PASS)).append(",\n");
        b.append("  \"review\": ").append(r.count(Status.REVIEW)).append(",\n");
        b.append("  \"failed\": ").append(r.count(Status.FAIL)).append(",\n");
        b.append("  \"hosts\": [\n");
        for (int i = 0; i < r.hosts.size(); i++) {
            HostResult h = r.hosts.get(i);
            b.append("    {\"target\": ").append(Json.quote(h.target))
                    .append(", \"status\": ").append(Json.quote(h.status().name())).append(", \"findings\": [");
            for (int j = 0; j < h.findings.size(); j++) {
                Finding f = h.findings.get(j);
                b.append(j == 0 ? "\n" : ",\n");
                b.append("      {\"template\": ").append(Json.quote(f.templateId))
                        .append(", \"name\": ").append(Json.quote(f.name))
                        .append(", \"severity\": ").append(Json.quote(f.severity))
                        .append(", \"matched_at\": ").append(Json.quote(f.matchedAt))
                        .append(", \"matcher\": ").append(Json.quote(f.matcher))
                        .append(", \"evidence\": [");
                for (int k = 0; k < f.extracted.size(); k++) {
                    b.append(k == 0 ? "" : ", ").append(Json.quote(f.extracted.get(k)));
                }
                b.append("], \"remediation\": ").append(Json.quote(f.remediation)).append('}');
            }
            b.append(h.findings.isEmpty() ? "]" : "\n    ]").append('}').append(i + 1 < r.hosts.size() ? ",\n" : "\n");
        }
        b.append("  ]\n}\n");
        return b.toString();
    }

    /** Escapes text for HTML. Evidence comes from remote devices, so it must be treated as untrusted. */
    static String esc(String s) {
        StringBuilder b = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch (c) {
                case '&': b.append("&amp;"); break;
                case '<': b.append("&lt;"); break;
                case '>': b.append("&gt;"); break;
                case '"': b.append("&quot;"); break;
                case '\'': b.append("&#39;"); break;
                default: b.append(c);
            }
        }
        return b.toString();
    }

    /** Self-contained HTML report: no scripts, no external resources. */
    static String renderHtml(Report r) {
        StringBuilder b = new StringBuilder();
        b.append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
                .append("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">")
                .append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
                .append("<title>DOOH Perimeter Diagnostic Audit</title><style>")
                .append("body{font:15px/1.5 system-ui,sans-serif;margin:2rem auto;max-width:60rem;padding:0 1rem;color:#1a1a1a}")
                .append("h1{font-size:1.4rem}.sum{margin:1rem 0;color:#444}")
                .append(".host{border:1px solid #ddd;border-radius:6px;margin:.6rem 0;padding:.6rem .9rem}")
                .append(".tag{font-weight:700;padding:.1rem .5rem;border-radius:4px;color:#fff;margin-right:.5rem}")
                .append(".PASS{background:#2e7d32}.REVIEW{background:#b26a00}.FAIL{background:#c62828}")
                .append(".f{margin:.5rem 0 .2rem 1rem}.ev,.fix{margin-left:1rem;color:#333}code{background:#f3f3f3;padding:0 .25rem}")
                .append("small{color:#555}</style></head><body><h1>DOOH Perimeter Diagnostic Audit</h1>");
        b.append("<p class=\"sum\">").append(r.count(Status.PASS)).append(" passed &middot; ")
                .append(r.count(Status.REVIEW)).append(" review &middot; ")
                .append(r.count(Status.FAIL)).append(" failed (of ").append(r.hosts.size()).append(") &middot; mode: ")
                .append(r.intrusive ? "intrusive" : "detection only").append("</p>");
        for (HostResult h : r.hosts) {
            Status s = h.status();
            b.append("<div class=\"host\"><span class=\"tag ").append(s).append("\">").append(s).append("</span><strong>")
                    .append(esc(h.target)).append("</strong>");
            if (s == Status.PASS) {
                b.append(" <small>No exposed DOOH management interfaces found</small>");
            }
            for (Finding f : h.findings) {
                b.append("<div class=\"f\"><strong>").append(esc(f.severity.toUpperCase(Locale.ROOT))).append("</strong>: ")
                        .append(esc(f.name)).append("</div><div class=\"ev\">Evidence: <code>").append(esc(f.matchedAt)).append("</code>");
                if (!f.matcher.isEmpty()) b.append(" (matcher: ").append(esc(f.matcher)).append(')');
                if (!f.extracted.isEmpty()) b.append(" &rarr; ").append(esc(String.join(", ", f.extracted)));
                b.append("</div>");
                if (!f.remediation.isEmpty()) b.append("<div class=\"fix\">Fix: ").append(esc(f.remediation)).append("</div>");
            }
            b.append("</div>");
        }
        for (String w : r.warnings) b.append("<p>Warning: ").append(esc(w)).append("</p>");
        b.append("<p><small>A finding means the service answered from where you scanned; from inside your own network it does not by itself prove it is reachable from the internet. PASS means none of this tool's checks matched, not that the device is secure.</small></p>");
        return b.append("</body></html>\n").toString();
    }

    /** Stand-alone use: {@code DOOHReportPrinter results.jsonl targets.txt}. */
    public static void main(String[] args) throws IOException {
        if (args.length < 2) {
            System.err.println("Usage: DOOHReportPrinter <results.jsonl> <targets.txt>");
            System.exit(2);
        }
        TargetParser.Result t = TargetParser.parse(Files.readAllLines(Path.of(args[1]), StandardCharsets.UTF_8));
        if (!t.errors.isEmpty()) {
            t.errors.forEach(e -> System.err.println("Invalid target: " + e));
            System.exit(2);
        }
        System.out.print(renderText(build(t.targets, Path.of(args[0]), false)));
    }
}
