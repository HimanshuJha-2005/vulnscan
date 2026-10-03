package com.himanshu.vulnscan.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class ServiceFingerprint {

    private final int port;
    private final String protocol;
    private final String product;
    private final String version;
    private final double confidence;
    private final String rawBanner;
    private final List<String> tags;

    @JsonCreator
    public ServiceFingerprint(
            @JsonProperty("port") int port,
            @JsonProperty("protocol") String protocol,
            @JsonProperty("product") String product,
            @JsonProperty("version") String version,
            @JsonProperty("confidence") double confidence,
            @JsonProperty("rawBanner") String rawBanner,
            @JsonProperty("tags") List<String> tags) {
        this.port = port;
        this.protocol = protocol;
        this.product = product;
        this.version = version;
        this.confidence = confidence;
        this.rawBanner = rawBanner;
        this.tags = tags;
    }

    public int getPort() { return port; }
    public String getProtocol() { return protocol; }
    public String getProduct() { return product; }
    public String getVersion() { return version; }
    public double getConfidence() { return confidence; }
    public String getRawBanner() { return rawBanner; }
    public List<String> getTags() { return tags; }
}