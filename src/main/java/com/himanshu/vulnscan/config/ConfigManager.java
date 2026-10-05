package com.himanshu.vulnscan.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ConfigManager {

    private static final Logger log = LoggerFactory.getLogger(ConfigManager.class);

    private static final ObjectMapper YAML_MAPPER = new ObjectMapper(new YAMLFactory());
    private static final String CONFIG_DIR = System.getProperty("user.home") + "/.vulnscan";
    private static final String CONFIG_FILE = CONFIG_DIR + "/config.yaml";

    private ScannerConfig config;

    public ConfigManager() {
        load();
    }

    public void load() {
        try {
            Path path = Paths.get(CONFIG_FILE);
            if (Files.exists(path)) {
                config = YAML_MAPPER.readValue(path.toFile(), ScannerConfig.class);
                log.info("Loaded config from {}", CONFIG_FILE);
            } else {
                config = createDefaultConfig();
                save();
                log.info("Created default config at {}", CONFIG_FILE);
            }
        } catch (IOException e) {
            log.warn("Failed to load config, using defaults: {}", e.getMessage());
            config = createDefaultConfig();
        }
    }

    public void save() {
        try {
            Files.createDirectories(Paths.get(CONFIG_DIR));
            YAML_MAPPER.writerWithDefaultPrettyPrinter().writeValue(Paths.get(CONFIG_FILE).toFile(), config);
            log.info("Saved config to {}", CONFIG_FILE);
        } catch (IOException e) {
            log.error("Failed to save config: {}", e.getMessage());
        }
    }

    public ScannerConfig getConfig() {
        return config;
    }

    public void setConfig(ScannerConfig config) {
        this.config = config;
        save();
    }

    public void updateProfile(String name, ScannerConfig.ScanProfile profile) {
        config.getProfiles().put(name, profile);
        save();
    }

    public void removeProfile(String name) {
        config.getProfiles().remove(name);
        save();
    }

    public void setEnabledChecks(List<String> checks) {
        config.getChecks().enabled().clear();
        config.getChecks().enabled().addAll(checks);
        save();
    }

    public void setDisabledChecks(List<String> checks) {
        config.getChecks().disabled().clear();
        config.getChecks().disabled().addAll(checks);
        save();
    }

    private ScannerConfig createDefaultConfig() {
        Map<String, ScannerConfig.ScanProfile> profiles = new HashMap<>();
        profiles.put("quick", new ScannerConfig.ScanProfile("top100", 500, 1000, "Fast scan of top 100 ports"));
        profiles.put("full", new ScannerConfig.ScanProfile("top1000", 1000, 3000, "Comprehensive scan of top 1000 ports"));
        profiles.put("stealth", new ScannerConfig.ScanProfile("22,80,443,3389", 50, 10000, "Slow stealth scan of critical ports"));
        profiles.put("all", new ScannerConfig.ScanProfile("all", 2000, 5000, "Full port range scan (1-65535)"));
        return new ScannerConfig(
                new ScannerConfig.ScannerSettings("top1000", 1000, 3000, true),
                profiles,
                new ScannerConfig.CheckSettings(new ArrayList<>(List.of("*")), new ArrayList<>())
        );
    }
}