package com.himanshu.vulnscan.scanner;

import com.himanshu.vulnscan.model.PortScanResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class PortScannerTest {

    @Test
    void testParsePortSpecTop100() {
        Set<Integer> ports = PortScanner.parsePortSpec("top100");
        assertEquals(100, ports.size());
        assertTrue(ports.contains(80));
        assertTrue(ports.contains(443));
        assertTrue(ports.contains(22));
    }

    @Test
    void testParsePortSpecTop1000() {
        Set<Integer> ports = PortScanner.parsePortSpec("top1000");
        // Ports 1-1000 plus commonly-abused high ports (3306, 8080, ...).
        assertTrue(ports.size() >= 1000);
        assertTrue(ports.contains(80));
        assertTrue(ports.contains(443));
        assertTrue(ports.contains(8080));
        assertTrue(ports.contains(3306));
    }

    @Test
    void testParsePortSpecAll() {
        Set<Integer> ports = PortScanner.parsePortSpec("all");
        assertEquals(65535, ports.size());
        assertTrue(ports.contains(65535));
    }

    @ParameterizedTest
    @ValueSource(strings = {"80,443,8080", "1-100", "22,80-90,443"})
    void testParseCustomPortSpec(String spec) {
        Set<Integer> ports = PortScanner.parsePortSpec(spec);
        assertFalse(ports.isEmpty());
        ports.forEach(p -> assertTrue(p > 0 && p <= 65535));
    }

    @Test
    void testParsePortSpecInvalid() {
        assertThrows(IllegalArgumentException.class, () -> PortScanner.parsePortSpec("invalid"));
    }

    @Test
    void testPortScanResultOpen() {
        PortScanResult result = PortScanResult.open(80, "HTTP/1.1 200 OK");
        assertTrue(result.isOpen());
        assertEquals(80, result.getPort());
        assertEquals("HTTP/1.1 200 OK", result.getBanner());
    }

    @Test
    void testPortScanResultClosed() {
        PortScanResult result = PortScanResult.closed(80);
        assertFalse(result.isOpen());
        assertEquals(80, result.getPort());
        assertNull(result.getBanner());
    }
}