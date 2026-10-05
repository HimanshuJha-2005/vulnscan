package com.himanshu.vulnscan.scanner;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class TargetParserTest {

    @Test
    void testParseSingleIP() {
        List<String> targets = TargetParser.parse("192.168.1.1", null);
        assertEquals(List.of("192.168.1.1"), targets);
    }

    @Test
    void testParseCIDR() {
        List<String> targets = TargetParser.parse("192.168.1.0/30", null);
        assertEquals(2, targets.size());
        assertTrue(targets.contains("192.168.1.1"));
        assertTrue(targets.contains("192.168.1.2"));
    }

    @Test
    void testParseCIDR24() {
        List<String> targets = TargetParser.parse("10.0.0.0/24", null);
        assertEquals(254, targets.size());
    }

    @Test
    void testParseRange() {
        List<String> targets = TargetParser.parse("192.168.1.1-5", null);
        assertEquals(5, targets.size());
        assertEquals("192.168.1.1", targets.get(0));
        assertEquals("192.168.1.5", targets.get(4));
    }

    @Test
    void testParseHostname() throws Exception {
        List<String> targets = TargetParser.parse("localhost", null);
        assertFalse(targets.isEmpty());
        // localhost may resolve to 127.0.0.1 and/or ::1 depending on the host.
        assertTrue(targets.stream().allMatch(ip -> isValidIP(ip) || isValidIPv6(ip)));
    }

    @Test
    void testParseFile() throws IOException {
        Path tempFile = Files.createTempFile("targets", ".txt");
        Files.writeString(tempFile, "192.168.1.1\n10.0.0.0/30\n# comment\n\n192.168.1.10-12");

        List<String> targets = TargetParser.parse(null, tempFile.toString());
        assertEquals(6, targets.size()); // 1 + 2 + 3
        Files.delete(tempFile);
    }

    @Test
    void testParseFileWithComments() throws IOException {
        Path tempFile = Files.createTempFile("targets", ".txt");
        Files.writeString(tempFile, "# This is a comment\n192.168.1.1\n\n# Another comment\n10.0.0.1");

        List<String> targets = TargetParser.parse(null, tempFile.toString());
        assertEquals(2, targets.size());
        Files.delete(tempFile);
    }

    @Test
    void testParseInvalidTarget() {
        assertThrows(IllegalArgumentException.class, () -> TargetParser.parse("invalid-target", null));
    }

    @Test
    void testParseEmptyTarget() {
        assertThrows(IllegalArgumentException.class, () -> TargetParser.parse("", null));
    }

    @Test
    void testParseCIDRTooLarge() {
        List<String> targets = TargetParser.parse("10.0.0.0/8", null);
        assertEquals(65534, targets.size()); // Limited to 65536 - 2
    }

    private boolean isValidIP(String ip) {
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

    private boolean isValidIPv6(String ip) {
        return ip != null && ip.contains(":");
    }
}