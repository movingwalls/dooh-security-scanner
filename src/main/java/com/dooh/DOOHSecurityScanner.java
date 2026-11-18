package com.dooh;

import java.io.Console;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Command line wrapper around Nuclei for DOOH perimeter checks.
 *
 * <p>Nuclei is started once for the whole target list, with an argument list (never a shell
 * command line), so nothing in {@code targets.txt} can be executed. Only this project's templates
 * are loaded.
 *
 * <p>Exit codes: 0 = no FAIL, 1 = at least one FAIL, 2 = bad usage or invalid targets,
 * 3 = the scan could not run reliably (reported as ERROR, never as PASS).
 */
public final class DOOHSecurityScanner {

    static final String VERSION = "1.0.0-rc1";

    /** Hard-coded safety limits so low-power LED controllers and cellular links are not overloaded. */
    static final String[] SAFETY_FLAGS = {"-rate-limit", "10", "-c", "5", "-timeout", "4"};

    private static final Pattern TEMPLATE_LOAD_ERROR = Pattern.compile(
            "(?i)(\\[ERR\\]|\\[FTL\\]|error occurred (loading|parsing)|could not (load|parse|validate)|"
                    + "failed to (load|parse)|no templates (provided|found)|invalid template)");

    static final String NOTICE =
            "Only scan IP addresses and devices that you own or are explicitly authorised to test.\n"
                    + "Unauthorised scanning may be illegal. Moving Walls is not responsible for misuse.";

    private DOOHSecurityScanner() {
    }

    static final class Options {
        String targetsFile;
        String hosts;
        boolean discover;
        String templates;
        String nuclei;
        String out;
        boolean intrusive;
        boolean yes;
        boolean offline;
        boolean installOnly;
    }

    public static void main(String[] args) {
        System.exit(run(args));
    }

    static int run(String[] args) {
        Options o = new Options();
        try {
            if (!parseArgs(args, o)) {
                return 0; // --help / --version
            }
        } catch (IllegalArgumentException ex) {
            System.err.println("Error: " + ex.getMessage());
            System.err.println("Run with --help for usage.");
            return 2;
        }

        try {
            // 0. --install-nuclei: just make sure the pinned Nuclei is available.
            if (o.installOnly) {
                String path = locateNuclei(o);
                if (path == null) {
                    return 3;
                }
                System.out.println("Nuclei is ready: " + path);
                return 0;
            }

            // 1. Collect and validate targets (before anything is executed).
            List<String> rawTargets;
            if (o.discover) {
                rawTargets = LocalArpScanner.discover(o.yes);
                if (rawTargets == null) {
                    return 2;
                }
            } else if (o.targetsFile != null) {
                Path p = Paths.get(o.targetsFile);
                if (!Files.isRegularFile(p)) {
                    System.err.println("Error: targets file not found: " + p.toAbsolutePath());
                    return 2;
                }
                rawTargets = Files.readAllLines(p, StandardCharsets.UTF_8);
            } else {
                rawTargets = Arrays.asList(o.hosts.split(","));
            }
            TargetParser.Result parsed = TargetParser.parse(rawTargets);
            if (!parsed.errors.isEmpty()) {
                System.err.println("Invalid target(s) - nothing was scanned:");
                parsed.errors.forEach(e -> System.err.println("  " + e));
                return 2;
            }
            if (parsed.targets.isEmpty()) {
                System.err.println("Error: no targets to scan.");
                return 2;
            }

            // 2. Locate templates and Nuclei (downloading the pinned, checksum-verified Nuclei if needed).
            Path templates = resolveTemplates(o.templates);
            if (templates == null) {
                System.err.println("Error: templates directory not found. Use --templates <dir>.");
                return 2;
            }
            String nuclei = locateNuclei(o);
            if (nuclei == null) {
                return 3;
            }

            // 3. Show scope and ask for confirmation.
            if (!confirm(o, parsed.targets.size())) {
                System.err.println("Scan cancelled.");
                return 2;
            }

            // 4. Prepare the output folder.
            Path outDir = Paths.get(o.out != null ? o.out : "scans")
                    .resolve(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")))
                    .toAbsolutePath();
            Files.createDirectories(outDir);
            Path targetsFile = outDir.resolve("targets.txt");
            Files.write(targetsFile, parsed.targets, StandardCharsets.UTF_8);
            Path results = outDir.resolve("results.jsonl");

            // 5. Make sure every template loads. A broken template must never look like a pass.
            System.out.println("Checking templates...");
            List<String> validate = List.of(nuclei, "-validate", "-t", templates.toString(), "-nc", "-duc");
            int vExit = exec(validate, outDir.resolve("nuclei-validate.log"));
            String vLog = Files.readString(outDir.resolve("nuclei-validate.log"), StandardCharsets.UTF_8);
            if (vExit != 0 || TEMPLATE_LOAD_ERROR.matcher(vLog).find()) {
                return error("One or more templates failed to load, so the results would be unreliable.",
                        outDir.resolve("nuclei-validate.log"), vLog);
            }

            // 6. Run Nuclei once for all targets.
            List<String> cmd = new ArrayList<>(List.of(nuclei, "-l", targetsFile.toString(), "-t", templates.toString()));
            cmd.addAll(Arrays.asList(SAFETY_FLAGS));
            cmd.addAll(List.of("-silent", "-nc", "-ni", "-duc", "-jsonl", "-o", results.toString()));
            if (!o.intrusive) {
                cmd.addAll(List.of("-etags", "intrusive"));
            }
            System.out.println("Scanning " + parsed.targets.size() + " target(s)...");
            int exit = exec(cmd, outDir.resolve("nuclei.log"));
            String log = Files.readString(outDir.resolve("nuclei.log"), StandardCharsets.UTF_8);
            if (exit != 0 || TEMPLATE_LOAD_ERROR.matcher(log).find()) {
                return error("Nuclei reported an error (exit code " + exit + "), so the scan is incomplete.",
                        outDir.resolve("nuclei.log"), log);
            }

            // 7. Report.
            DOOHReportPrinter.Report report = DOOHReportPrinter.build(parsed.targets, results, o.intrusive);
            String text = DOOHReportPrinter.renderText(report);
            Files.writeString(outDir.resolve("report.txt"), text, StandardCharsets.UTF_8);
            Files.writeString(outDir.resolve("report.json"), DOOHReportPrinter.renderJson(report), StandardCharsets.UTF_8);
            Files.writeString(outDir.resolve("report.html"), DOOHReportPrinter.renderHtml(report), StandardCharsets.UTF_8);
            System.out.print(text);
            System.out.println("Saved: " + outDir.resolve("report.txt"));
            System.out.println("       " + outDir.resolve("report.html") + "  (open in a browser)");
            System.out.println("       " + outDir.resolve("report.json") + "  (machine-readable)");
            System.out.println("       " + results + "  (raw Nuclei findings)");
            return report.count(DOOHReportPrinter.Status.FAIL) > 0 ? 1 : 0;
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            System.err.println("[ERROR] " + e.getMessage());
            return 3;
        }
    }

    // ---------------------------------------------------------------- helpers

    private static int error(String message, Path logFile, String log) {
        System.err.println("[ERROR] " + message);
        System.err.println("        No PASS/FAIL result is given for this run. Details: " + logFile);
        String[] lines = log.strip().split("\\R");
        for (int i = Math.max(0, lines.length - 8); i < lines.length; i++) {
            System.err.println("        | " + lines[i]);
        }
        return 3;
    }

    private static boolean confirm(Options o, int count) {
        System.out.println();
        System.out.println(NOTICE);
        System.out.println("Targets: " + count + (o.discover ? " (discovered on the local network)" : ""));
        if (o.intrusive) {
            System.out.println("INTRUSIVE mode: default-password logins will be ATTEMPTED. Only continue if the");
            System.out.println("device owner has given written consent.");
        } else {
            System.out.println("Mode: detection only (no logins are attempted).");
        }
        if (o.yes) {
            return true;
        }
        Console c = System.console();
        if (c == null) {
            System.err.println("Non-interactive session: add --yes to confirm you are authorised to scan these targets.");
            return false;
        }
        String answer = c.readLine("Type YES to confirm you are authorised to scan these targets: ");
        return answer != null && answer.strip().equalsIgnoreCase("yes");
    }

    /**
     * Runs a command, never through a shell. Nuclei's diagnostics go to stderr and are saved to the
     * log file; its findings are written to the {@code -o} file, so stdout is discarded.
     */
    private static int exec(List<String> cmd, Path log) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectOutput(ProcessBuilder.Redirect.DISCARD);
        pb.redirectError(log.toFile());
        Process p = pb.start();
        Thread hook = new Thread(p::destroyForcibly); // Ctrl+C must not leave Nuclei running
        Runtime.getRuntime().addShutdownHook(hook);
        try {
            return p.waitFor();
        } finally {
            try {
                Runtime.getRuntime().removeShutdownHook(hook);
            } catch (IllegalStateException ignored) {
                // JVM already shutting down
            }
        }
    }

    /** Returns Nuclei's version output, or {@code null} when the executable cannot be run. */
    static String nucleiVersionOutput(String nuclei) {
        try {
            Path out = Files.createTempFile("dooh-nuclei-version", ".txt");
            try {
                ProcessBuilder pb = new ProcessBuilder(nuclei, "-version", "-duc", "-nc");
                pb.redirectErrorStream(true);
                pb.redirectOutput(out.toFile());
                Process p = pb.start();
                if (!p.waitFor(30, TimeUnit.SECONDS)) {
                    p.destroyForcibly();
                    return null;
                }
                return p.exitValue() == 0 ? Files.readString(out, StandardCharsets.UTF_8) : null;
            } finally {
                Files.deleteIfExists(out);
            }
        } catch (IOException ex) {
            return null;
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            return null;
        }
    }

    /**
     * Finds a working Nuclei: --nuclei, then next to the scanner, then the per-user cache, then PATH.
     * If none is found, offers to download the pinned, checksum-verified release (--yes approves,
     * --offline forbids). Returns {@code null} after printing an explanation when nothing works.
     */
    static String locateNuclei(Options o) {
        List<String> candidates = new ArrayList<>();
        if (o.nuclei != null) {
            candidates.add(o.nuclei);
        } else {
            for (Path dir : searchDirs()) {
                Path c = dir.resolve(NucleiInstaller.exeName());
                if (Files.isRegularFile(c)) {
                    candidates.add(c.toString());
                }
            }
            if (Files.isRegularFile(NucleiInstaller.installedBinary())) {
                candidates.add(NucleiInstaller.installedBinary().toString());
            }
            candidates.add(NucleiInstaller.exeName()); // PATH
        }
        for (String c : candidates) {
            String version = nucleiVersionOutput(c);
            if (version != null) {
                if (!version.contains(NucleiInstaller.VERSION)) {
                    System.err.println("Warning: this scanner is tested with Nuclei " + NucleiInstaller.VERSION
                            + "; found a different version at " + c + ". Results may differ.");
                }
                return c;
            }
        }
        if (o.nuclei != null) {
            System.err.println("[ERROR] Nuclei does not run: " + o.nuclei);
            return null;
        }
        return installNuclei(o);
    }

    private static String installNuclei(Options o) {
        String key = NucleiInstaller.platformKey();
        String manual = "Install Nuclei " + NucleiInstaller.VERSION + " from https://github.com/projectdiscovery/nuclei/releases/tag/v"
                + NucleiInstaller.VERSION + " and use --nuclei <path>.";
        if (key == null) {
            System.err.println("[ERROR] Nuclei was not found and no official build is pinned for this system. " + manual);
            return null;
        }
        if (o.offline) {
            System.err.println("[ERROR] Nuclei was not found and --offline forbids downloading it. " + manual);
            return null;
        }
        System.out.println();
        System.out.println("Nuclei (the open-source scan engine by ProjectDiscovery) was not found.");
        System.out.println("It can be downloaded now: " + NucleiInstaller.OFFICIAL_BASE + NucleiInstaller.assetName(key));
        System.out.println("The file is checked against a SHA-256 checksum built into this scanner and saved in:");
        System.out.println("  " + NucleiInstaller.installedBinary().getParent());
        if (!o.yes) {
            Console c = System.console();
            if (c == null) {
                System.err.println("Non-interactive session: add --yes to allow the download, or " + manual);
                return null;
            }
            String a = c.readLine("Download Nuclei " + NucleiInstaller.VERSION + " now? Type YES to continue: ");
            if (a == null || !a.strip().equalsIgnoreCase("yes")) {
                System.err.println("Download declined. " + manual);
                return null;
            }
        }
        try {
            System.out.println("Downloading...");
            Path bin = NucleiInstaller.install();
            if (nucleiVersionOutput(bin.toString()) == null) {
                System.err.println("[ERROR] The downloaded Nuclei does not run on this system"
                        + (NucleiInstaller.isWindows() ? " (your antivirus may have blocked it; allow-list nuclei.exe)." : "."));
                return null;
            }
            System.out.println("Installed and verified Nuclei " + NucleiInstaller.VERSION + ".");
            return bin.toString();
        } catch (IOException e) {
            System.err.println("[ERROR] Could not install Nuclei: " + e.getMessage());
            System.err.println("        " + manual);
            return null;
        }
    }

    static Path resolveTemplates(String explicit) {
        if (explicit != null) {
            Path p = Paths.get(explicit).toAbsolutePath();
            return hasTemplates(p) ? p : null;
        }
        for (Path dir : searchDirs()) {
            Path p = dir.resolve("templates");
            if (hasTemplates(p)) {
                return p;
            }
        }
        try { // single-jar use: templates packaged inside the jar
            Path extracted = TemplateStore.extractFromJar();
            return extracted != null && hasTemplates(extracted) ? extracted : null;
        } catch (IOException e) {
            System.err.println("Warning: could not extract the packaged templates: " + e.getMessage());
            return null;
        }
    }

    private static boolean hasTemplates(Path dir) {
        if (!Files.isDirectory(dir)) {
            return false;
        }
        try (Stream<Path> s = Files.walk(dir)) {
            return s.anyMatch(f -> f.toString().endsWith(".yaml"));
        } catch (IOException ex) {
            return false;
        }
    }

    /** Current directory first, then the folder containing the jar. */
    private static List<Path> searchDirs() {
        List<Path> dirs = new ArrayList<>();
        dirs.add(Paths.get("").toAbsolutePath());
        try {
            Path jar = Paths.get(DOOHSecurityScanner.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            Path parent = Files.isDirectory(jar) ? jar : jar.getParent();
            if (parent != null) {
                dirs.add(parent);
                if (parent.getParent() != null) {
                    dirs.add(parent.getParent()); // target/classes -> target -> project root
                    if (parent.getParent().getParent() != null) {
                        dirs.add(parent.getParent().getParent());
                    }
                }
            }
        } catch (URISyntaxException | RuntimeException ex) {
            // ignore: current directory only
        }
        return dirs;
    }

    static boolean parseArgs(String[] args, Options o) {
        if (args.length == 0) {
            usage();
            throw new IllegalArgumentException("no target given (use -t, -h or --discover)");
        }
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            switch (a) {
                case "-t": case "--targets": o.targetsFile = value(args, ++i, a); break;
                case "-h": case "--hosts": o.hosts = value(args, ++i, a); break;
                case "--discover": o.discover = true; break;
                case "--templates": o.templates = value(args, ++i, a); break;
                case "--nuclei": o.nuclei = value(args, ++i, a); break;
                case "--out": o.out = value(args, ++i, a); break;
                case "--intrusive": o.intrusive = true; break;
                case "--yes": case "-y": o.yes = true; break;
                case "--offline": o.offline = true; break;
                case "--install-nuclei": o.installOnly = true; break;
                case "--help": usage(); return false;
                case "--version": System.out.println("dooh-security-scanner " + VERSION); return false;
                default: throw new IllegalArgumentException("unknown option: " + a);
            }
        }
        if (o.installOnly) {
            return true;
        }
        int sources = (o.targetsFile != null ? 1 : 0) + (o.hosts != null ? 1 : 0) + (o.discover ? 1 : 0);
        if (sources != 1) {
            throw new IllegalArgumentException("give exactly one of -t <file>, -h <hosts> or --discover");
        }
        return true;
    }

    private static String value(String[] args, int i, String opt) {
        if (i >= args.length) {
            throw new IllegalArgumentException(opt + " needs a value");
        }
        return args[i];
    }

    private static void usage() {
        System.out.println("DOOH Security Scanner " + VERSION);
        System.out.println();
        System.out.println("Usage: java -jar dooh-security-scanner.jar (-t targets.txt | -h host[,host...] | --discover) [options]");
        System.out.println();
        System.out.println("Targets (one source required):");
        System.out.println("  -t, --targets <file>   file with one IPv4 address, CIDR block (/22-/32) or host name per line");
        System.out.println("  -h, --hosts <list>     comma-separated targets, e.g. 203.0.113.10,203.0.113.0/28");
        System.out.println("      --discover         find devices on your local network first (shows the network, asks to confirm)");
        System.out.println();
        System.out.println("Options:");
        System.out.println("      --intrusive        also try vendor default passwords (ONLY with the owner's written consent)");
        System.out.println("      --templates <dir>  template folder (default: ./templates, else the templates packaged in the jar)");
        System.out.println("      --nuclei <path>    Nuclei executable (default: next to the scanner, cached copy, then PATH;");
        System.out.println("                         if none is found the pinned Nuclei " + NucleiInstaller.VERSION + " is downloaded and checksum-verified)");
        System.out.println("      --install-nuclei   download/verify Nuclei now and exit");
        System.out.println("      --offline          never download anything");
        System.out.println("      --out <dir>        output folder (default: ./scans)");
        System.out.println("  -y, --yes              skip the confirmation prompt (you confirm you are authorised)");
        System.out.println("      --version          print the version");
        System.out.println();
        System.out.println(NOTICE);
    }
}
