package com.himanshu.vulnscan.check;

import com.himanshu.vulnscan.model.Finding;
import com.himanshu.vulnscan.model.ServiceFingerprint;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CheckRegistryTest {

    @Test
    void testBuiltInChecksLoaded() {
        CheckRegistry registry = new CheckRegistry();
        assertTrue(registry.getTotalCount() >= 10);
    }

    @Test
    void testGetEnabledChecks() {
        CheckRegistry registry = new CheckRegistry();
        List<VulnerabilityCheck> enabled = registry.getEnabledChecks();
        assertFalse(enabled.isEmpty());
        assertTrue(enabled.stream().allMatch(VulnerabilityCheck::isEnabled));
    }

    @Test
    void testGetCheckById() {
        CheckRegistry registry = new CheckRegistry();
        Optional<VulnerabilityCheck> check = registry.getCheck("CVE-2021-44228");
        assertTrue(check.isPresent());
        assertEquals("Log4Shell RCE", check.get().metadata().name());
    }

    @Test
    void testDisableEnableCheck() {
        CheckRegistry registry = new CheckRegistry();
        String id = "CVE-2021-44228";

        registry.disableCheck(id);
        assertFalse(registry.getEnabledChecks().stream().anyMatch(c -> c.metadata().id().equals(id)));

        registry.enableCheck(id);
        assertTrue(registry.getEnabledChecks().stream().anyMatch(c -> c.metadata().id().equals(id)));
    }

    @Test
    void testEnableOnly() {
        CheckRegistry registry = new CheckRegistry();
        registry.enableOnly(List.of("CVE-2021-44228", "ANON-FTP"));
        assertEquals(2, registry.getEnabledChecks().size());
    }

    @Test
    void testExecuteChecksAnonymousFtp() {
        CheckRegistry registry = new CheckRegistry();
        ServiceFingerprint fp = new ServiceFingerprint(
                21, "ftp", "vsftpd", "3.0.5", 0.9, "220 (vsFTPd 3.0.5)\n230 Login successful", List.of("ftp")
        );
        List<Finding> findings = registry.executeChecks(fp);
        assertTrue(findings.stream().anyMatch(f -> f.getCheckId().equals("ANON-FTP")));
    }

    @Test
    void testExecuteChecksRedisUnauth() {
        CheckRegistry registry = new CheckRegistry();
        ServiceFingerprint fp = new ServiceFingerprint(
                6379, "redis", "Redis", "7.0.12", 0.95, "redis_version:7.0.12", List.of("redis", "database")
        );
        List<Finding> findings = registry.executeChecks(fp);
        assertTrue(findings.stream().anyMatch(f -> f.getCheckId().equals("REDIS-UNAUTH")));
    }

    @Test
    void testExecuteChecksMongoOpen() {
        CheckRegistry registry = new CheckRegistry();
        ServiceFingerprint fp = new ServiceFingerprint(
                27017, "mongodb", "MongoDB", "6.0.5", 0.9, "MongoDB 6.0.5", List.of("mongodb", "database")
        );
        List<Finding> findings = registry.executeChecks(fp);
        assertTrue(findings.stream().anyMatch(f -> f.getCheckId().equals("MONGO-OPEN")));
    }

    @Test
    void testFilterByTag() {
        CheckRegistry registry = new CheckRegistry();
        var webChecks = registry.getChecksByTag("web");
        assertTrue(webChecks.size() >= 3);
    }

    @Test
    void testCheckMetadata() {
        CheckRegistry registry = new CheckRegistry();
        VulnerabilityCheck check = registry.getCheck("CVE-2021-44228").orElseThrow();
        assertEquals(Severity.CRITICAL, check.metadata().severity());
        assertEquals(10.0, check.metadata().cvss());
        assertTrue(check.metadata().tags().contains("critical"));
    }
}