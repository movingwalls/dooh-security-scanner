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

    static final String VERSION = "1.0.0-rc3";

    /** Hard-coded safety limits so low-power LED controllers and cellular links are not overloaded. */
    static final String[] SAFETY_FLAGS = {"-rate-limit", "10", "-c", "5", "-timeout", "4"};

    private static final Pattern TEMPLATE_LOAD_ERROR = Pattern.compile(
            "(?i)(\\[ERR\\]|\\[FTL\\]|error occurred (loading|parsing)|could not (load|parse|validate)|"
                    + "failed to (load|parse)|no templates (provided|found)|invalid template)");

    static final String NOTICE =
            "Only scan IP addresses and devices that you own or are explicitly authorised to test.\n"
                    + "Unauthorised scanning may be illegal. Moving Walls is not responsible for misuse.";

    /** Null device used as the child's stdin so Nuclei never waits for piped input. */
    private static final ProcessBuilder.Redirect NULL_INPUT = ProcessBuilder.Redirect.from(
            new java.io.File(System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win") ? "NUL" : "/dev/null"));

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
        /** null = the tested version; "latest" or an exact version only when asked for. */
        String nucleiVersion;
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
            // 0. --install-nuclei: fetch (or update to) the wanted Nuclei and exit.
            if (o.installOnly) {
                // Asking for the latest means "update now"; otherwise reuse a trusted copy if there is one.
                boolean update = "latest".equals(o.nucleiVersion) && o.nuclei == null && !o.offline;
                String path = update ? installNuclei(o) : locateNuclei(o);
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
        pb.redirectInput(NULL_INPUT); // Nuclei waits for piped stdin to close if it is left open
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
                pb.redirectInput(NULL_INPUT);
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
     * Finds a Nuclei to run. With {@code --nuclei <path>} that exact file is used (the user chose it; a warning is
     * printed when it is not the official build). Otherwise only <em>trusted</em> copies are considered, in this
     * order: next to the scanner's jar, the scanner's own cache, then absolute {@code PATH} entries. The current
     * folder is never searched. Trusted means it matches the official SHA-256 (see
     * {@link NucleiInstaller#isTrusted}); anything else found is skipped with a notice. If nothing trusted is found,
     * the official release is offered for download ({@code --yes} approves, {@code --offline} forbids). Returns
     * {@code null} after printing an explanation when nothing works.
     */
    static String locateNuclei(Options o) {
        if (o.nuclei != null) {
            String version = nucleiVersionOutput(o.nuclei);
            if (version == null) {
                System.err.println("[ERROR] Nuclei does not run: " + o.nuclei);
                return null;
            }
            if (!NucleiInstaller.isTrusted(Paths.get(o.nuclei))) {
                System.err.println("Warning: running the Nuclei you chose (" + o.nuclei + "); it was not checked against the"
                        + " official build, so make sure you trust where it came from.");
            }
            warnIfOlder(version, o.nuclei);
            return o.nuclei;
        }
        for (Path c : candidateNuclei(o)) {
            if (!NucleiInstaller.isTrusted(c)) {
                System.err.println("Skipping " + c + ": it is not the official Nuclei build this scanner trusts.");
                continue;
            }
            String version = nucleiVersionOutput(c.toString());
            if (version != null) {
                warnIfOlder(version, c.toString());
                return c.toString();
            }
        }
        return installNuclei(o);
    }

    private static void warnIfOlder(String versionOutput, String where) {
        String found = NucleiInstaller.versionIn(versionOutput);
        if (found != null && NucleiInstaller.compareVersions(found, NucleiInstaller.VERSION) < 0) {
            System.err.println("Warning: this scanner is tested with Nuclei " + NucleiInstaller.VERSION
                    + " or newer; found older version " + found + " at " + where + ". Results may differ.");
        }
    }

    /** Absolute paths only; never the working folder. */
    private static List<Path> candidateNuclei(Options o) {
        List<Path> out = new ArrayList<>();
        Path jarDir = jarDir();
        if (jarDir != null) {
            Path c = jarDir.resolve(NucleiInstaller.exeName());
            if (Files.isRegularFile(c)) {
                out.add(c);
            }
        }
        if (o.nucleiVersion == null) {
            Path tested = NucleiInstaller.installedBinary();
            if (Files.isRegularFile(tested)) {
                out.add(tested);
            }
        } else if ("latest".equals(o.nucleiVersion)) {
            out.addAll(NucleiInstaller.installedBinaries());
        } else {
            Path exact = NucleiInstaller.installedBinary(o.nucleiVersion);
            if (Files.isRegularFile(exact)) {
                out.add(exact);
            }
        }
        out.addAll(NucleiInstaller.pathCandidates(System.getenv("PATH"), Paths.get("")));
        return out;
    }

    private static String installNuclei(Options o) {
        boolean latest = "latest".equals(o.nucleiVersion);
        String version = o.nucleiVersion == null ? NucleiInstaller.VERSION : o.nucleiVersion;
        String wanted = latest ? "the latest version" : "version " + version;
        String manual = "Install Nuclei from https://github.com/projectdiscovery/nuclei/releases and use --nuclei <path>.";
        String key = NucleiInstaller.platformKey();
        if (key == null) {
            System.err.println("[ERROR] Nuclei was not found and no official build is available for this system ("
                    + System.getProperty("os.name") + "/" + System.getProperty("os.arch") + "). " + manual);
            return null;
        }
        if (o.offline) {
            System.err.println("[ERROR] Nuclei was not found and --offline forbids downloading it. " + manual);
            return null;
        }
        System.out.println();
        System.out.println("Nuclei (the open-source scan engine by ProjectDiscovery) is needed.");
        System.out.println("It can be downloaded now (" + wanted + ", build for " + key + ") from the official page:");
        System.out.println("  https://github.com/projectdiscovery/nuclei/releases");
        System.out.println(latest
                ? "The file is checked against the SHA-256 checksum published with that release and saved in:"
                : "The file is checked against SHA-256 checksums built into this scanner and saved in:");
        System.out.println("  " + NucleiInstaller.cacheRoot().resolve("nuclei"));
        if (!o.yes) {
            Console c = System.console();
            if (c == null) {
                System.err.println("Non-interactive session: add --yes to allow the download, or " + manual);
                return null;
            }
            String a = c.readLine("Download Nuclei " + wanted + " now? Type YES to continue: ");
            if (a == null || !a.strip().equalsIgnoreCase("yes")) {
                System.err.println("Download declined. " + manual);
                return null;
            }
        }
        try {
            System.out.println("Downloading...");
            Path bin = latest ? NucleiInstaller.installLatest() : NucleiInstaller.installVersion(version);
            String out = nucleiVersionOutput(bin.toString());
            if (out == null) {
                System.err.println("[ERROR] The downloaded Nuclei does not run on this system"
                        + (NucleiInstaller.isWindows() ? " (your antivirus may have blocked it; allow-list nuclei.exe)." : "."));
                return null;
            }
            System.out.println("Installed and verified Nuclei " + NucleiInstaller.versionIn(out) + ".");
            return bin.toString();
        } catch (IOException e) {
            System.err.println("[ERROR] Could not install Nuclei: " + e.getMessage());
            System.err.println("        " + manual);
            return null;
        }
    }

    /**
     * Templates to load. {@code --templates <dir>} is used as given. Otherwise the templates packaged in the jar are
     * used, after being re-checked against the jar on every run. The working folder is never searched. A
     * {@code templates/} folder next to the jar is only a fallback for a jar without packaged templates, and the
     * project folder is searched only when running from build output (development).
     */
    static Path resolveTemplates(String explicit) {
        if (explicit != null) {
            Path p = Paths.get(explicit).toAbsolutePath();
            return hasTemplates(p) ? p : null;
        }
        try {
            Path extracted = TemplateStore.extractFromJar();
            if (extracted != null && hasTemplates(extracted)) {
                return extracted;
            }
        } catch (IOException e) {
            System.err.println("Warning: could not extract the packaged templates: " + e.getMessage());
        }
        for (Path dir : templateFallbackDirs()) {
            if (hasTemplates(dir)) {
                return dir;
            }
        }
        return null;
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

    /** Where the scanner's code lives: a jar file, or a build-output folder when run from an IDE or Maven. */
    private static Path codeLocation() {
        try {
            return Paths.get(DOOHSecurityScanner.class.getProtectionDomain().getCodeSource().getLocation().toURI())
                    .toAbsolutePath().normalize();
        } catch (URISyntaxException | RuntimeException ex) {
            return null;
        }
    }

    /** The folder containing the jar, or {@code null} when not running from a jar. */
    private static Path jarDir() {
        Path loc = codeLocation();
        return loc != null && Files.isRegularFile(loc) ? loc.getParent() : null;
    }

    private static List<Path> templateFallbackDirs() {
        List<Path> dirs = new ArrayList<>();
        Path loc = codeLocation();
        if (loc == null) {
            return dirs;
        }
        if (Files.isRegularFile(loc)) {
            if (loc.getParent() != null) {
                dirs.add(loc.getParent().resolve("templates")); // jar without packaged templates
            }
        } else { // build output: target/classes (templates are copied in) or the project folder above it
            dirs.add(loc.resolve("templates"));
            if (loc.getParent() != null && loc.getParent().getParent() != null) {
                dirs.add(loc.getParent().getParent().resolve("templates"));
            }
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
                case "--nuclei-version": {
                    String v = value(args, ++i, a);
                    if (!"latest".equals(v) && !NucleiInstaller.isPlainVersion(v)) {
                        throw new IllegalArgumentException("--nuclei-version must be 'latest' or a version like 3.4.10");
                    }
                    o.nucleiVersion = v;
                    break;
                }
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
        System.out.println("      --templates <dir>  template folder (default: the templates packaged in the jar)");
        System.out.println("      --nuclei <path>    Nuclei executable to run as given (default: only the official build is used,");
        System.out.println("                         found next to the jar, in the cache or on PATH, never in the current folder;");
        System.out.println("                         if none is found the tested Nuclei " + NucleiInstaller.VERSION + " is downloaded and checksum-verified)");
        System.out.println("      --install-nuclei   download/verify Nuclei now and exit");
        System.out.println("      --nuclei-version <v>  use/download 'latest' or an exact version instead of the tested " + NucleiInstaller.VERSION);
        System.out.println("      --offline          never download anything");
        System.out.println("      --out <dir>        output folder (default: ./scans)");
        System.out.println("  -y, --yes              skip the confirmation prompt (you confirm you are authorised)");
        System.out.println("      --version          print the version");
        System.out.println();
        System.out.println(NOTICE);
    }
}
