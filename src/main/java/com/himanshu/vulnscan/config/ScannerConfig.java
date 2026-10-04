package com.himanshu.vulnscan.config;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

public class ScannerConfig {

    private final ScannerSettings scanner;
    private final Map<String, ScanProfile> profiles;
    private final CheckSettings checks;

    @JsonCreator
    public ScannerConfig(
            @JsonProperty("scanner") ScannerSettings scanner,
            @JsonProperty("profiles") Map<String, ScanProfile> profiles,
            @JsonProperty("checks") CheckSettings checks) {
        this.scanner = scanner != null ? scanner : new ScannerSettings();
        this.profiles = profiles != null ? profiles : Map.of();
        this.checks = checks != null ? checks : new CheckSettings();
    }

    public ScannerSettings getScanner() { return scanner; }
    public Map<String, ScanProfile> getProfiles() { return profiles; }
    public CheckSettings getChecks() { return checks; }

    public record ScannerSettings(
            String defaultPorts,
            int defaultThreads,
            int defaultTimeout,
            boolean bannerGrab
    ) {
        public ScannerSettings() {
            this("top1000", 1000, 3000, true);
        }
    }

    public record ScanProfile(
            String ports,
            int threads,
            int timeout,
            String description
    ) {}

    public record CheckSettings(
            List<String> enabled,
            List<String> disabled
    ) {
        public CheckSettings() {
            this(List.of("*"), List.of());
        }
    }
}