package com.himanshu.vulnscan.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.Map;
import java.util.List;

public class ScanResult {

    private final String scanId;
    private final String target;
    private final String inputFile;
    private final String ports;
    private final String profile;
    private final Instant startTime;
    private final Instant endTime;
    private final Map<String, List<PortScanResult>> portResults;
    private final Map<String, List<ServiceFingerprint>> fingerprints;
    private final Map<String, List<Finding>> findings;

    @JsonCreator
    public ScanResult(
            @JsonProperty("scanId") String scanId,
            @JsonProperty("target") String target,
            @JsonProperty("inputFile") String inputFile,
            @JsonProperty("ports") String ports,
            @JsonProperty("profile") String profile,
            @JsonProperty("startTime") Instant startTime,
            @JsonProperty("endTime") Instant endTime,
            @JsonProperty("portResults") Map<String, List<PortScanResult>> portResults,
            @JsonProperty("fingerprints") Map<String, List<ServiceFingerprint>> fingerprints,
            @JsonProperty("findings") Map<String, List<Finding>> findings) {
        this.scanId = scanId;
        this.target = target;
        this.inputFile = inputFile;
        this.ports = ports;
        this.profile = profile;
        this.startTime = startTime;
        this.endTime = endTime;
        this.portResults = portResults;
        this.fingerprints = fingerprints;
        this.findings = findings;
    }

    public String getScanId() { return scanId; }
    public String getTarget() { return target; }
    public String getInputFile() { return inputFile; }
    public String getPorts() { return ports; }
    public String getProfile() { return profile; }
    public Instant getStartTime() { return startTime; }
    public Instant getEndTime() { return endTime; }
    public long getDurationMs() { return java.time.Duration.between(startTime, endTime).toMillis(); }
    public Map<String, List<PortScanResult>> getPortResults() { return portResults; }
    public Map<String, List<ServiceFingerprint>> getFingerprints() { return fingerprints; }
    public Map<String, List<Finding>> getFindings() { return findings; }

    public int getTotalHosts() { return portResults.size(); }
    public int getTotalOpenPorts() {
        return portResults.values().stream()
                .flatMap(List::stream)
                .mapToInt(r -> r.isOpen() ? 1 : 0)
                .sum();
    }
    public int getTotalFindings() {
        return findings.values().stream().mapToInt(List::size).sum();
    }
    public int getCriticalFindings() {
        return findings.values().stream()
                .flatMap(List::stream)
                .mapToInt(f -> f.getSeverity() == VulnerabilityCheck.Severity.CRITICAL ? 1 : 0)
                .sum();
    }
    public int getHighFindings() {
        return findings.values().stream()
                .flatMap(List::stream)
                .mapToInt(f -> f.getSeverity() == VulnerabilityCheck.Severity.HIGH ? 1 : 0)
                .sum();
    }
}