package com.himanshu.vulnscan;

import com.himanshu.vulnscan.config.ConfigManager;
import com.himanshu.vulnscan.config.ScannerConfig;
import com.himanshu.vulnscan.persistence.ScanStateStore;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.util.concurrent.Callable;

@Command(name = "config",
        description = "Manage scanner configuration",
        mixinStandardHelpOptions = true,
        subcommands = {
                ConfigGetCommand.class,
                ConfigSetCommand.class,
                ConfigListCommand.class,
                ConfigProfilesCommand.class,
                ConfigResetCommand.class
        })
public class ConfigCommand implements Callable<Integer> {

    @Override
    public Integer call() {
        System.out.println("Config management - use subcommand: get, set, list, profiles, reset");
        return 0;
    }
}

@Command(name = "get", description = "Get configuration value")
class ConfigGetCommand implements Callable<Integer> {
    @Parameters(index = "0", description = "Configuration key (e.g., scanner.defaultPorts, profiles.quick.ports)")
    private String key;

    @Override
    public Integer call() {
        ConfigManager manager = new ConfigManager();
        ScannerConfig config = manager.getConfig();

        String value = switch (key) {
            case "scanner.defaultPorts" -> config.getScanner().defaultPorts();
            case "scanner.defaultThreads" -> String.valueOf(config.getScanner().defaultThreads());
            case "scanner.defaultTimeout" -> String.valueOf(config.getScanner().defaultTimeout());
            case "scanner.bannerGrab" -> String.valueOf(config.getScanner().bannerGrab());
            default -> {
                if (key.startsWith("profiles.")) {
                    String profileName = key.substring("profiles.".length());
                    ScannerConfig.ScanProfile profile = config.getProfiles().get(profileName);
                    if (profile != null) {
                        yield profile.ports() + "," + profile.threads() + "," + profile.timeout();
                    }
                    yield "Profile not found: " + profileName;
                }
                yield "Unknown key: " + key;
            }
        };
        System.out.println(value);
        return 0;
    }
}

@Command(name = "set", description = "Set configuration value")
class ConfigSetCommand implements Callable<Integer> {
    @Parameters(index = "0", description = "Configuration key")
    private String key;

    @Parameters(index = "1", description = "Configuration value")
    private String value;

    @Override
    public Integer call() {
        ConfigManager manager = new ConfigManager();
        ScannerConfig config = manager.getConfig();

        switch (key) {
            case "scanner.defaultPorts" -> {
                var newScanner = new ScannerConfig.ScannerSettings(
                        value, config.getScanner().defaultThreads(), config.getScanner().defaultTimeout(), config.getScanner().bannerGrab()
                );
                manager.setConfig(new ScannerConfig(newScanner, config.getProfiles(), config.getChecks()));
            }
            case "scanner.defaultThreads" -> {
                var newScanner = new ScannerConfig.ScannerSettings(
                        config.getScanner().defaultPorts(), Integer.parseInt(value), config.getScanner().defaultTimeout(), config.getScanner().bannerGrab()
                );
                manager.setConfig(new ScannerConfig(newScanner, config.getProfiles(), config.getChecks()));
            }
            case "scanner.defaultTimeout" -> {
                var newScanner = new ScannerConfig.ScannerSettings(
                        config.getScanner().defaultPorts(), config.getScanner().defaultThreads(), Integer.parseInt(value), config.getScanner().bannerGrab()
                );
                manager.setConfig(new ScannerConfig(newScanner, config.getProfiles(), config.getChecks()));
            }
            case "scanner.bannerGrab" -> {
                var newScanner = new ScannerConfig.ScannerSettings(
                        config.getScanner().defaultPorts(), config.getScanner().defaultThreads(), config.getScanner().defaultTimeout(), Boolean.parseBoolean(value)
                );
                manager.setConfig(new ScannerConfig(newScanner, config.getProfiles(), config.getChecks()));
            }
            default -> {
                System.err.println("Unknown key: " + key);
                return 1;
            }
        }
        System.out.println("Set " + key + " = " + value);
        return 0;
    }
}

@Command(name = "list", description = "List all configuration")
class ConfigListCommand implements Callable<Integer> {
    @Override
    public Integer call() {
        ConfigManager manager = new ConfigManager();
        ScannerConfig config = manager.getConfig();

        System.out.println("=== Scanner Settings ===");
        System.out.println("  defaultPorts: " + config.getScanner().defaultPorts());
        System.out.println("  defaultThreads: " + config.getScanner().defaultThreads());
        System.out.println("  defaultTimeout: " + config.getScanner().defaultTimeout() + "ms");
        System.out.println("  bannerGrab: " + config.getScanner().bannerGrab());

        System.out.println("\n=== Profiles ===");
        for (Map.Entry<String, ScannerConfig.ScanProfile> entry : config.getProfiles().entrySet()) {
            ScannerConfig.ScanProfile p = entry.getValue();
            System.out.println("  " + entry.getKey() + ": ports=" + p.ports() + ", threads=" + p.threads() + ", timeout=" + p.timeout() + "ms (" + p.description() + ")");
        }

        System.out.println("\n=== Checks ===");
        System.out.println("  enabled: " + config.getChecks().enabled());
        System.out.println("  disabled: " + config.getChecks().disabled());

        return 0;
    }
}

@Command(name = "profiles", description = "Manage scan profiles")
class ConfigProfilesCommand implements Callable<Integer> {
    @Option(names = {"--add"}, description = "Add profile: name,ports,threads,timeout,description")
    private String add;

    @Option(names = {"--remove"}, description = "Remove profile by name")
    private String remove;

    @Override
    public Integer call() {
        ConfigManager manager = new ConfigManager();

        if (add != null) {
            String[] parts = add.split(",");
            if (parts.length != 5) {
                System.err.println("Usage: --add name,ports,threads,timeout,description");
                return 1;
            }
            manager.updateProfile(parts[0], new ScannerConfig.ScanProfile(
                    parts[1], Integer.parseInt(parts[2]), Integer.parseInt(parts[3]), parts[4]
            ));
            System.out.println("Added profile: " + parts[0]);
        } else if (remove != null) {
            manager.removeProfile(remove);
            System.out.println("Removed profile: " + remove);
        } else {
            System.out.println("Use --add or --remove");
        }
        return 0;
    }
}

@Command(name = "reset", description = "Reset configuration to defaults")
class ConfigResetCommand implements Callable<Integer> {
    @Option(names = {"--force"}, description = "Skip confirmation")
    private boolean force;

    @Override
    public Integer call() {
        if (!force) {
            System.out.print("This will reset all configuration to defaults. Continue? [y/N] ");
            try {
                int input = System.in.read();
                if (input != 'y' && input != 'Y') {
                    System.out.println("Cancelled");
                    return 0;
                }
            } catch (Exception e) {
                return 1;
            }
        }

        ConfigManager manager = new ConfigManager();
        // Delete config file and let it recreate
        java.nio.file.Files.deleteIfExists(java.nio.file.Paths.get(System.getProperty("user.home"), ".vulnscan", "config.yaml"));
        manager.load(); // Recreates defaults
        System.out.println("Configuration reset to defaults");
        return 0;
    }
}