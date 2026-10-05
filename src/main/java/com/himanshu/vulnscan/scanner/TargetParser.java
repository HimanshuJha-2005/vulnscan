package com.himanshu.vulnscan.scanner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class TargetParser {

    private static final Logger log = LoggerFactory.getLogger(TargetParser.class);

    public static List<String> parse(String target, String inputFile) {
        if (inputFile != null && !inputFile.isBlank()) {
            return parseFile(inputFile);
        }

        if (target == null || target.isBlank()) {
            throw new IllegalArgumentException("Target or input file must be specified");
        }

        return parseTarget(target);
    }

    private static List<String> parseTarget(String target) {
        target = target.trim();

        if (target.contains("/")) {
            return expandCIDR(target);
        }

        // Last-octet range: 192.168.1.1-50
        if (target.matches("^\\d+\\.\\d+\\.\\d+\\.\\d+-\\d+$")) {
            return expandRange(target);
        }

        if (isHostname(target)) {
            return resolveHostname(target);
        }

        if (isValidIP(target)) {
            return List.of(target);
        }

        throw new IllegalArgumentException("Invalid target format: " + target);
    }

    private static List<String> expandCIDR(String cidr) {
        String[] parts = cidr.split("/");
        String ip = parts[0];
        int prefix = Integer.parseInt(parts[1]);

        if (prefix < 0 || prefix > 32) {
            throw new IllegalArgumentException("Invalid CIDR prefix: " + prefix);
        }

        byte[] ipBytes = parseIP(ip);
        int hostBits = 32 - prefix;
        long numHosts = 1L << hostBits;

        if (numHosts > 65536) {
            log.warn("CIDR {} expands to {} hosts, limiting to first 65536", cidr, numHosts);
            numHosts = 65536;
        }

        List<String> hosts = new ArrayList<>();
        long network = bytesToLong(ipBytes) & (~0L << hostBits);

        for (long i = 1; i < numHosts - 1; i++) {
            long hostLong = network | i;
            hosts.add(longToIP(hostLong));
        }

        log.info("CIDR {} expanded to {} hosts", cidr, hosts.size());
        return hosts;
    }

    private static List<String> expandRange(String range) {
        String[] parts = range.split("-");
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid range format: " + range);
        }

        String baseIP = parts[0];
        int lastOctetStart = Integer.parseInt(parts[1]);

        String[] octets = baseIP.split("\\.");
        if (octets.length != 4) {
            throw new IllegalArgumentException("Invalid IP in range: " + baseIP);
        }

        String prefix = octets[0] + "." + octets[1] + "." + octets[2] + ".";
        int lastOctetBase = Integer.parseInt(octets[3]);

        List<String> hosts = new ArrayList<>();
        for (int i = lastOctetBase; i <= lastOctetStart; i++) {
            hosts.add(prefix + i);
        }

        log.info("Range {} expanded to {} hosts", range, hosts.size());
        return hosts;
    }

    private static List<String> resolveHostname(String hostname) {
        try {
            InetAddress[] addresses = InetAddress.getAllByName(hostname);
            List<String> ips = Stream.of(addresses)
                    .map(InetAddress::getHostAddress)
                    .distinct()
                    .collect(Collectors.toList());
            log.info("Resolved {} to {} IP(s)", hostname, ips.size());
            return ips;
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Failed to resolve hostname: " + hostname, e);
        }
    }

    private static List<String> parseFile(String filePath) {
        try {
            return Files.readAllLines(Path.of(filePath)).stream()
                    .map(String::trim)
                    .filter(line -> !line.isEmpty() && !line.startsWith("#"))
                    .flatMap(TargetParser::parseTargetStream)
                    .distinct()
                    .collect(Collectors.toList());
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to read input file: " + filePath, e);
        }
    }

    private static Stream<String> parseTargetStream(String line) {
        try {
            return parseTarget(line).stream();
        } catch (Exception e) {
            log.warn("Skipping invalid target in file: {} ({})", line, e.getMessage());
            return Stream.empty();
        }
    }

    private static boolean isValidIP(String ip) {
        String[] octets = ip.split("\\.");
        if (octets.length != 4) return false;
        for (String octet : octets) {
            try {
                int val = Integer.parseInt(octet);
                if (val < 0 || val > 255) return false;
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return true;
    }

    private static boolean isHostname(String target) {
        return !isValidIP(target) && target.matches("^[a-zA-Z0-9.-]+$");
    }

    private static byte[] parseIP(String ip) {
        String[] octets = ip.split("\\.");
        byte[] bytes = new byte[4];
        for (int i = 0; i < 4; i++) {
            bytes[i] = (byte) Integer.parseInt(octets[i]);
        }
        return bytes;
    }

    private static long bytesToLong(byte[] bytes) {
        long result = 0;
        for (byte b : bytes) {
            result = (result << 8) | (b & 0xFF);
        }
        return result;
    }

    private static String longToIP(long value) {
        return ((value >> 24) & 0xFF) + "." +
                ((value >> 16) & 0xFF) + "." +
                ((value >> 8) & 0xFF) + "." +
                (value & 0xFF);
    }
}