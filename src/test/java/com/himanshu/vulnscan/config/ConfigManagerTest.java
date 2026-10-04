package com.himanshu.vulnscan.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ConfigManagerTest {

    @Test
    void testDefaultConfigCreation(@TempDir Path tempDir) throws Exception {
        // Use a custom config dir for testing
        System.setProperty("user.home", tempDir.toString());

        ConfigManager manager = new ConfigManager();
        ScannerConfig config = manager.getConfig();

        assertNotNull(config.getScanner());
        assertEquals("top1000", config.getScanner().defaultPorts());
        assertEquals(1000, config.getScanner().defaultThreads());

        assertTrue(config.getProfiles().containsKey("quick"));
        assertTrue(config.getProfiles().containsKey("full"));
        assertTrue(config.getProfiles().containsKey("stealth"));

        assertEquals(List.of("*"), config.getChecks().enabled());
    }

    @Test
    void testProfileManagement(@TempDir Path tempDir) {
        System.setProperty("user.home", tempDir.toString());

        ConfigManager manager = new ConfigManager();
        manager.updateProfile("custom", new ScannerConfig.ScanProfile("80,443", 100, 5000, "Custom web scan"));

        ConfigManager manager2 = new ConfigManager();
        assertTrue(manager2.getConfig().getProfiles().containsKey("custom"));
        assertEquals("80,443", manager2.getConfig().getProfiles().get("custom").ports());
    }

    @Test
    void testCheckSettings(@TempDir Path tempDir) {
        System.setProperty("user.home", tempDir.toString());

        ConfigManager manager = new ConfigManager();
        manager.setEnabledChecks(List.of("CVE-2021-44228", "ANON-FTP"));
        manager.setDisabledChecks(List.of("DEFAULT-CREDS"));

        ConfigManager manager2 = new ConfigManager();
        assertEquals(List.of("CVE-2021-44228", "ANON-FTP"), manager2.getConfig().getChecks().enabled());
        assertEquals(List.of("DEFAULT-CREDS"), manager2.getConfig().getChecks().disabled());
    }
}