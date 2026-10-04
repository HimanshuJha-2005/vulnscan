package com.himanshu.vulnscan;

import com.himanshu.vulnscan.check.CheckRegistry;
import com.himanshu.vulnscan.check.VulnerabilityCheck;
import com.himanshu.vulnscan.output.OutputFormatter;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.util.concurrent.Callable;

@Command(name = "list-checks",
        description = "List available vulnerability checks",
        mixinStandardHelpOptions = true)
public class ListChecksCommand implements Callable<Integer> {

    @Option(names = {"-c", "--category"}, description = "Filter by category (web, database, network, auth, config, rce, crypto, misconfiguration, info-leak)")
    private String category;

    @Option(names = {"--show-disabled"}, description = "Include disabled checks")
    private boolean showDisabled = false;

    @Option(names = {"--format"}, description = "Output format: table, json, csv")
    private String format = "table";

    @Override
    public Integer call() {
        CheckRegistry registry = new CheckRegistry();
        OutputFormatter formatter = new OutputFormatter();

        List<VulnerabilityCheck> checks = showDisabled ? registry.getAllChecks() : registry.getEnabledChecks();

        if (category != null && !category.isBlank()) {
            checks = checks.stream()
                    .filter(c -> c.metadata().tags().contains(category.toLowerCase()))
                    .toList();
        }

        System.out.println("Total checks: " + checks.size());
        System.out.println();

        if (format.equalsIgnoreCase("json")) {
            System.out.println(formatter.formatChecksJson(checks));
        } else if (format.equalsIgnoreCase("csv")) {
            System.out.println(formatter.formatChecksCsv(checks));
        } else {
            System.out.println(formatter.formatChecksTable(checks));
        }

        return 0;
    }
}