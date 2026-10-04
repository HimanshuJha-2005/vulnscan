package com.himanshu.vulnscan.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class Finding {

    private final String checkId;
    private final String checkName;
    private final VulnerabilityCheck.Severity severity;
    private final double cvss;
    private final String title;
    private final String description;
    private final String evidence;
    private final List<String> references;
    private final List<String> tags;
    private final long timestamp;

    @JsonCreator
    public Finding(
            @JsonProperty("checkId") String checkId,
            @JsonProperty("checkName") String checkName,
            @JsonProperty("severity") VulnerabilityCheck.Severity severity,
            @JsonProperty("cvss") double cvss,
            @JsonProperty("title") String title,
            @JsonProperty("description") String description,
            @JsonProperty("evidence") String evidence,
            @JsonProperty("references") List<String> references,
            @JsonProperty("tags") List<String> tags) {
        this.checkId = checkId;
        this.checkName = checkName;
        this.severity = severity;
        this.cvss = cvss;
        this.title = title;
        this.description = description;
        this.evidence = evidence;
        this.references = references;
        this.tags = tags;
        this.timestamp = System.currentTimeMillis();
    }

    public static Finding fromCheck(VulnerabilityCheck.CheckMetadata metadata, String evidence, String description) {
        return new Finding(
                metadata.id(),
                metadata.name(),
                metadata.severity(),
                metadata.cvss(),
                metadata.name(),
                description != null ? description : metadata.description(),
                evidence,
                metadata.references(),
                metadata.tags()
        );
    }

    public String getCheckId() { return checkId; }
    public String getCheckName() { return checkName; }
    public VulnerabilityCheck.Severity getSeverity() { return severity; }
    public double getCvss() { return cvss; }
    public String getTitle() { return title; }
    public String getDescription() { return description; }
    public String getEvidence() { return evidence; }
    public List<String> getReferences() { return references; }
    public List<String> getTags() { return tags; }
    public long getTimestamp() { return timestamp; }
}