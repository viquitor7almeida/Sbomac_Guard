package dev.sbomguard.manifest;

import java.util.List;

public record Manifest(
        int schemaVersion,
        String created,
        Tool tool,
        Subject subject,
        SbomRef sbom,
        List<ManifestComponent> components) {

    public record Tool(String name, String version) {
    }

    public record Subject(String group, String name, String version, String purl, String path, String sha256) {
    }

    public record SbomRef(String path, String sha256) {
    }
}
