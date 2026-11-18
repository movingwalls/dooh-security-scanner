package com.dooh;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Validates and expands the user-supplied target list.
 *
 * <p>Only plain IPv4 addresses, IPv4 CIDR blocks and DNS host names are accepted. Anything else
 * (spaces, shell metacharacters, URLs, ports, option-like text) is rejected before Nuclei is
 * started, and targets are always handed to Nuclei as list-file entries, never through a shell.
 */
final class TargetParser {
    /** Largest CIDR block accepted (/22 = 1024 addresses). */
    static final int MIN_PREFIX = 22;
    /** Maximum number of distinct targets in one scan. */
    static final int MAX_TARGETS = 4096;

    private static final Pattern HOSTNAME = Pattern.compile(
            "^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$");
    private static final Pattern DIGITS_AND_DOTS = Pattern.compile("^[0-9.]+(/[0-9]+)?$");

    private TargetParser() {
    }

    static final class Result {
        final List<String> targets = new ArrayList<>();
        final List<String> errors = new ArrayList<>();
    }

    static Result parse(List<String> lines) {
        Result r = new Result();
        Set<String> seen = new LinkedHashSet<>();
        int lineNo = 0;
        for (String raw : lines) {
            lineNo++;
            String line = raw.strip();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            try {
                seen.addAll(expand(line));
            } catch (IllegalArgumentException ex) {
                r.errors.add("line " + lineNo + ": " + ex.getMessage());
            }
            if (seen.size() > MAX_TARGETS) {
                r.errors.add("more than " + MAX_TARGETS + " targets; split the list into smaller scans");
                break;
            }
        }
        r.targets.addAll(seen);
        return r;
    }

    /** Expands one entry (IPv4, CIDR or host name) to individual targets. */
    static List<String> expand(String entry) {
        List<String> out = new ArrayList<>();
        if (DIGITS_AND_DOTS.matcher(entry).matches()) {
            String addr = entry;
            int prefix = 32;
            int slash = entry.indexOf('/');
            if (slash >= 0) {
                addr = entry.substring(0, slash);
                try {
                    prefix = Integer.parseInt(entry.substring(slash + 1));
                } catch (NumberFormatException ex) {
                    throw new IllegalArgumentException("invalid prefix length in '" + safe(entry) + "'");
                }
                if (prefix < MIN_PREFIX || prefix > 32) {
                    throw new IllegalArgumentException("'" + safe(entry) + "': prefix must be between /" + MIN_PREFIX
                            + " and /32 (at most " + (1 << (32 - MIN_PREFIX)) + " addresses)");
                }
            }
            long ip = ipv4ToLong(addr);
            if (ip < 0) {
                throw new IllegalArgumentException("'" + safe(entry) + "' is not a valid IPv4 address");
            }
            long mask = prefix == 0 ? 0 : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
            long network = ip & mask;
            long broadcast = network | (~mask & 0xFFFFFFFFL);
            long first = network;
            long last = broadcast;
            if (prefix <= 30) { // skip network and broadcast addresses
                first++;
                last--;
            }
            for (long a = first; a <= last; a++) {
                if (!isScannable(a)) {
                    if (prefix == 32) {
                        throw new IllegalArgumentException("'" + safe(entry)
                                + "' is a multicast, broadcast or reserved address and cannot be scanned");
                    }
                    continue;
                }
                out.add(longToIpv4(a));
            }
            return out;
        }
        if (HOSTNAME.matcher(entry).matches()) {
            out.add(entry.toLowerCase(java.util.Locale.ROOT));
            return out;
        }
        throw new IllegalArgumentException("'" + safe(entry)
                + "' is not an IPv4 address, CIDR block (e.g. 192.0.2.0/24) or host name");
    }

    /** Returns the address as an unsigned 32-bit value, or -1 when it is not dotted-quad IPv4. */
    static long ipv4ToLong(String s) {
        String[] p = s.split("\\.", -1);
        if (p.length != 4) {
            return -1;
        }
        long v = 0;
        for (String part : p) {
            if (part.isEmpty() || part.length() > 3) {
                return -1;
            }
            int n;
            try {
                n = Integer.parseInt(part);
            } catch (NumberFormatException ex) {
                return -1;
            }
            if (n < 0 || n > 255) {
                return -1;
            }
            v = (v << 8) | n;
        }
        return v;
    }

    static String longToIpv4(long v) {
        return ((v >> 24) & 255) + "." + ((v >> 16) & 255) + "." + ((v >> 8) & 255) + "." + (v & 255);
    }

    /** Rejects 0.0.0.0/8, multicast (224/4) and reserved/broadcast (240/4). Loopback stays allowed for testing. */
    static boolean isScannable(long ip) {
        long first = ip >> 24;
        return first != 0 && first < 224;
    }

    /** Keeps error messages printable even when the input contains control characters. */
    private static String safe(String s) {
        String t = s.length() > 60 ? s.substring(0, 60) + "..." : s;
        return t.replaceAll("[^\\x20-\\x7E]", "?");
    }
}
