package com.dooh;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Enumeration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LocalArpScanner {

    public static void main(String[] args) {
        try {
            String localIp = getLocalIPv4Address();
            if (localIp == null) {
                System.out.println("Could not determine local IPv4 address.");
                return;
            }
            System.out.println("Local IP: " + localIp);
            String subnet = localIp.substring(0, localIp.lastIndexOf("."));

            // 1. Trigger ARP requests across the /24 subnet to populate the OS ARP cache
            System.out.println("Scanning subnet " + subnet + ".0/24...");
            populateArpCache(subnet);

            // 2. Read, parse, and write the OS ARP table to a text file
            String outputFile = "targets.txt";
            System.out.println("\nDiscovered Devices (IP -> MAC):");
            readAndSaveArpTable(outputFile);
            System.out.println("\nSaved IP addresses to " + outputFile);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String getLocalIPv4Address() throws Exception {
        Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
        while (interfaces.hasMoreElements()) {
            NetworkInterface iface = interfaces.nextElement();
            if (iface.isLoopback() || !iface.isUp()) continue;

            Enumeration<InetAddress> addresses = iface.getInetAddresses();
            while (addresses.hasMoreElements()) {
                InetAddress addr = addresses.nextElement();
                if (addr instanceof Inet4Address && addr.isSiteLocalAddress()) {
                    return addr.getHostAddress();
                }
            }
        }
        return null;
    }

    private static void populateArpCache(String subnet) throws InterruptedException {
        ExecutorService executor = Executors.newFixedThreadPool(50);

        for (int i = 1; i < 255; i++) {
            final String host = subnet + "." + i;
            executor.submit(() -> {
                try {
                    InetAddress.getByName(host).isReachable(500);
                } catch (Exception ignored) {
                }
            });
        }

        executor.shutdown();
        executor.awaitTermination(10, TimeUnit.SECONDS);
    }

    private static void readAndSaveArpTable(String filePath) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("arp", "-a");
        Process process = pb.start();

        Pattern pattern = Pattern.compile(
            "(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}).*?(([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})"
        );

        // Open both the process reader and the file writer safely
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
             BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
            
            String line;
            while ((line = reader.readLine()) != null) {
                Matcher matcher = pattern.matcher(line);
                if (matcher.find()) {
                    String ip = matcher.group(1);
                    String mac = matcher.group(2);

                    if (!mac.equalsIgnoreCase("ff-ff-ff-ff-ff-ff") && !mac.equalsIgnoreCase("ff:ff:ff:ff:ff:ff")) {
                        // Print to console
                        System.out.printf("%-16s -> %s%n", ip, mac);
                        
                        // Write only the IP address to the file
                        writer.write(ip);
                        writer.newLine();
                    }
                }
            }
        }
    }
}