package com.himanshu.vulnscan.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class PortScanResult {

    private final int port;
    private final boolean open;
    private final String banner;
    private final long timestamp;

    private PortScanResult(int port, boolean open, String banner) {
        this.port = port;
        this.open = open;
        this.banner = banner;
        this.timestamp = System.currentTimeMillis();
    }

    @JsonCreator
    public static PortScanResult open(@JsonProperty("port") int port, @JsonProperty("banner") String banner) {
        return new PortScanResult(port, true, banner);
    }

    public static PortScanResult closed(int port) {
        return new PortScanResult(port, false, null);
    }

    public int getPort() { return port; }
    public boolean isOpen() { return open; }
    public String getBanner() { return banner; }
    public long getTimestamp() { return timestamp; }
}