package com.dooh;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.TreeSet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Optional helper that lists devices on the machine's own LAN.
 *
 * <p>It only looks at the real subnet of the primary physical network adapter, ignores VPN and
 * virtual adapters, never reports multicast/broadcast addresses, and always shows the network and
 * asks before probing it.
 */
public final class LocalArpScanner {

    private static final Pattern VIRTUAL_NAME = Pattern.compile(
            "(?i)(vpn|tun\\d|tap|tailscale|zerotier|wireguard|^wg\\d|docker|veth|virbr|vbox|virtualbox|vmware|vmnet"
                    + "|hyper-v|vethernet|utun|ppp|^br-|bridge|loopback|teredo|isatap|npcap|pseudo)");
    private static final Pattern IP_MAC = Pattern.compile(
            "(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}).*?(([0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2})");

    private LocalArpScanner() {
    }

    /** A usable LAN: our own address plus the subnet it belongs to. */
    static final class Lan {
        final String iface;
        final long ip;
        final int prefix;

        Lan(String iface, long ip, int prefix) {
            this.iface = iface;
            this.ip = ip;
            this.prefix = prefix;
        }

        long mask() {
            return (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
        }

        long network() {
            return ip & mask();
        }

        long broadcast() {
            return network() | (~mask() & 0xFFFFFFFFL);
        }

        boolean contains(long other) {
            return (other & mask()) == network();
        }

        String cidr() {
            return TargetParser.longToIpv4(network()) + "/" + prefix;
        }
    }

    /** Stand-alone: writes the discovered addresses to targets.txt after confirmation. */
    public static void main(String[] args) throws IOException {
        boolean yes = args.length > 0 && (args[0].equals("--yes") || args[0].equals("-y"));
        List<String> found = discover(yes);
        if (found == null) {
            System.exit(2);
        }
        Path out = Paths.get("targets.txt");
        if (Files.exists(out) && !yes) {
            Console c = System.console();
            String a = c == null ? null : c.readLine("targets.txt already exists. Overwrite? (yes/no): ");
            if (a == null || !a.strip().equalsIgnoreCase("yes")) {
                System.out.println("Not overwritten. Discovered addresses:");
                found.forEach(System.out::println);
                return;
            }
        }
        Files.write(out, found, StandardCharsets.UTF_8);
        System.out.println("Saved " + found.size() + " address(es) to " + out.toAbsolutePath());
    }

    /**
     * Shows the network, asks for confirmation, then returns the live addresses on it.
     *
     * @return the addresses, or {@code null} when discovery was cancelled or not possible
     */
    static List<String> discover(boolean assumeYes) {
        Lan lan = findLan();
        if (lan == null) {
            System.err.println("Could not find a local IPv4 network. Provide targets with -t or -h instead.");
            return null;
        }
        long hosts = (1L << (32 - lan.prefix)) - 2;
        System.out.println("Network adapter : " + lan.iface);
        System.out.println("Your address    : " + TargetParser.longToIpv4(lan.ip));
        System.out.println("Network to scan : " + lan.cidr() + " (" + hosts + " addresses)");
        if (lan.prefix < TargetParser.MIN_PREFIX) {
            System.err.println("This network is larger than /" + TargetParser.MIN_PREFIX
                    + ". Automatic discovery is limited to that size; provide targets with -t or -h instead.");
            return null;
        }
        if (!assumeYes) {
            Console c = System.console();
            if (c == null) {
                System.err.println("Non-interactive session: add --yes to confirm discovery of " + lan.cidr() + ".");
                return null;
            }
            String a = c.readLine("Probe this network to find devices? Type YES to continue: ");
            if (a == null || !a.strip().equalsIgnoreCase("yes")) {
                System.err.println("Discovery cancelled.");
                return null;
            }
        }
        try {
            populateArpCache(lan);
            List<String> found = readArpTable(lan);
            System.out.println("Discovered " + found.size() + " device(s) on " + lan.cidr() + ".");
            return found;
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            System.err.println("Discovery failed: " + e.getMessage());
            return null;
        }
    }

    /** Picks the first up, non-virtual, non-VPN interface with a private IPv4 address. */
    static Lan findLan() {
        try {
            Enumeration<NetworkInterface> ifaces = NetworkInterface.getNetworkInterfaces();
            if (ifaces == null) {
                return null;
            }
            for (NetworkInterface nif : Collections.list(ifaces)) {
                if (!nif.isUp() || nif.isLoopback() || nif.isVirtual() || nif.isPointToPoint()
                        || VIRTUAL_NAME.matcher(nif.getName()).find()
                        || VIRTUAL_NAME.matcher(String.valueOf(nif.getDisplayName())).find()) {
                    continue;
                }
                for (InterfaceAddress ia : nif.getInterfaceAddresses()) {
                    InetAddress addr = ia.getAddress();
                    int prefix = ia.getNetworkPrefixLength();
                    if (addr instanceof Inet4Address && addr.isSiteLocalAddress() && prefix >= 8 && prefix <= 30) {
                        return new Lan(nif.getDisplayName(), TargetParser.ipv4ToLong(addr.getHostAddress()), prefix);
                    }
                }
            }
        } catch (java.net.SocketException e) {
            // fall through
        }
        return null;
    }

    /** Pings every address in the subnet so the OS fills its ARP table. */
    private static void populateArpCache(Lan lan) throws InterruptedException {
        System.out.println("Probing " + lan.cidr() + " ...");
        ExecutorService pool = Executors.newFixedThreadPool(50);
        for (long a = lan.network() + 1; a < lan.broadcast(); a++) {
            final String host = TargetParser.longToIpv4(a);
            pool.submit(() -> {
                try {
                    InetAddress.getByName(host).isReachable(500);
                } catch (IOException ignored) {
                    // unreachable hosts are expected
                }
            });
        }
        pool.shutdown();
        pool.awaitTermination(60, TimeUnit.SECONDS);
    }

    /** Reads the ARP table and keeps only real unicast neighbours inside our subnet. */
    private static List<String> readArpTable(Lan lan) throws IOException {
        TreeSet<Long> found = new TreeSet<>();
        for (String line : arpLines()) {
            Matcher m = IP_MAC.matcher(line);
            if (!m.find()) {
                continue;
            }
            long ip = TargetParser.ipv4ToLong(m.group(1));
            String mac = m.group(2).toLowerCase(Locale.ROOT).replace('-', ':');
            if (ip < 0 || !lan.contains(ip) || ip == lan.ip || ip == lan.network() || ip == lan.broadcast()
                    || !TargetParser.isScannable(ip)
                    || mac.equals("ff:ff:ff:ff:ff:ff") || mac.equals("00:00:00:00:00:00")
                    || mac.startsWith("01:00:5e")) { // 01:00:5e = IPv4 multicast MAC
                continue;
            }
            found.add(ip);
        }
        List<String> out = new ArrayList<>();
        for (long ip : found) {
            out.add(TargetParser.longToIpv4(ip));
        }
        return out;
    }

    private static List<String> arpLines() throws IOException {
        Path procArp = Paths.get("/proc/net/arp"); // Linux: available even without the arp tool
        if (Files.isReadable(procArp)) {
            List<String> lines = new ArrayList<>();
            for (String l : Files.readAllLines(procArp, StandardCharsets.UTF_8)) {
                String[] f = l.trim().split("\\s+");
                // IP, HW type, Flags, HW address, Mask, Device; flags 0x0 = incomplete entry
                if (f.length >= 4 && !f[2].equals("0x0")) {
                    lines.add(f[0] + " " + f[3]);
                }
            }
            return lines;
        }
        Process p = new ProcessBuilder("arp", "-a").redirectErrorStream(true).start();
        List<String> lines = new ArrayList<>();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            String l;
            while ((l = r.readLine()) != null) {
                lines.add(l);
            }
        }
        return lines;
    }
}
