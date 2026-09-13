package dev.sbomguard.verification;

import dev.sbomguard.crypto.HashService;
import dev.sbomguard.manifest.Manifest;
import dev.sbomguard.manifest.ManifestComponent;
import dev.sbomguard.scanner.Component;
import dev.sbomguard.scanner.ProjectScanner.ScanResult;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import dev.sbomguard.scanner.Component.ComponentType;

public final class VerificationEngine {

    public enum FindingKind {
        HASH_DIVERGENTE, COMPONENTE_AUSENTE, COMPONENTE_INESPERADO, SBOM_DIVERGENTE, SBOM_AUSENTE
    }

    public record Finding(FindingKind kind, String message) {
    }

    public List<Finding> verify(Manifest manifest, ScanResult atual, Path sbomArquivo) throws IOException {
        List<Finding> findings = new ArrayList<>();
        Path root = atual.root();

        verificarSbom(manifest, sbomArquivo, findings);
        verificarSujeito(manifest, atual, root, findings);
        verificarComponents(manifest, atual, root, findings);

        return List.copyOf(findings);
    }

    private void verificarSbom(Manifest manifest, Path sbomArquivo, List<Finding> findings)
            throws IOException {
        if (sbomArquivo == null || manifest.sbom() == null) {
            return;
        }
        if (!Files.isRegularFile(sbomArquivo)) {
            findings.add(new Finding(FindingKind.SBOM_AUSENTE,
                    "SBOM atestado não existe: " + sbomArquivo));
            return;
        }
        String hashAtual = HashService.sha256Hex(sbomArquivo);
        if (!manifest.sbom().sha256().equals(hashAtual)) {
            findings.add(new Finding(FindingKind.SBOM_DIVERGENTE,
                    "hash do SBOM diverge do registrado no manifesto (esperado "
                            + prefixo(manifest.sbom().sha256()) + ", atual " + prefixo(hashAtual) + ")"));
        }
    }

    private void verificarSujeito(Manifest manifest, ScanResult atual, Path root, List<Finding> findings)
            throws IOException {
        if (manifest.subject() == null) {
            if (atual.subject().isPresent()) {
                findings.add(new Finding(FindingKind.COMPONENTE_INESPERADO,
                        "pom não atestado presente: " + descreve(atual.subject().orElseThrow())));
            }
            return;
        }
        Path pom = root.resolve(manifest.subject().path());
        if (!Files.isRegularFile(pom)) {
            findings.add(new Finding(FindingKind.COMPONENTE_AUSENTE,
                    "pom do sujeito ausente: " + manifest.subject().path()));
            return;
        }
        String hashAtual = HashService.sha256Hex(pom);
        if (!manifest.subject().sha256().equals(hashAtual)) {
            findings.add(new Finding(FindingKind.HASH_DIVERGENTE,
                    "pom do sujeito diverge do atestado: " + manifest.subject().path()
                            + " — declarações alteradas? (esperado "
                            + prefixo(manifest.subject().sha256()) + ", atual " + prefixo(hashAtual) + ")"));
        }
    }

    private void verificarComponents(Manifest manifest, ScanResult atual, Path root, List<Finding> findings)
            throws IOException {
        Map<String, ManifestComponent> esperados = new LinkedHashMap<>();
        for (ManifestComponent c : manifest.components()) {
            esperados.put(chave(c.type(), c.purl(), c.path()), c);
        }

        Map<String, Component> atuais = new LinkedHashMap<>();
        Component sujeitoAtual = atual.subject().orElse(null);
        for (Component c : atual.components()) {
            if (c.equals(sujeitoAtual)) {
                continue;
            }
            atuais.put(chave(c.type(), c.purl(), c.path() == null ? null : c.path().toString()), c);
        }

        for (Map.Entry<String, ManifestComponent> entry : esperados.entrySet()) {
            ManifestComponent esperado = entry.getValue();
            if (!atuais.containsKey(entry.getKey())) {
                findings.add(new Finding(FindingKind.COMPONENTE_AUSENTE,
                        "componente atestado ausente: " + descreve(esperado)));
            } else if (esperado.sha256() != null) {
                String hashAtual = HashService.sha256Hex(root.resolve(esperado.path()));
                if (!esperado.sha256().equals(hashAtual)) {
                    findings.add(new Finding(FindingKind.HASH_DIVERGENTE,
                            "hash divergente: " + descreve(esperado) + " (esperado "
                                    + prefixo(esperado.sha256()) + ", atual " + prefixo(hashAtual) + ")"));
                }
            }
        }
        for (Map.Entry<String, Component> entry : atuais.entrySet()) {
            if (!esperados.containsKey(entry.getKey())) {
                findings.add(new Finding(FindingKind.COMPONENTE_INESPERADO,
                        "componente não atestado presente: " + descreve(entry.getValue())));
            }
        }
    }

    private String chave(String type, String purl, String path) {
        if (ManifestComponent.TYPE_MAVEN_DEPENDENCY.equals(type)) {
            return "purl:" + purl;
        }
        return "path:" + path;
    }

    private String chave(ComponentType type, String purl, String path) {
        if (type == ComponentType.MAVEN_DEPENDENCY) {
            return "purl:" + purl;
        }
        return "path:" + path;
    }

    private String descreve(ManifestComponent c) {
        String identidade = c.purl() != null ? c.purl() : c.path();
        return "[" + c.type() + "] " + (c.group() != null ? c.group() + ":" : "") + c.name()
                + (c.version() != null ? ":" + c.version() : "") + " (" + identidade + ")";
    }

    private String descreve(Component c) {
        String identidade = c.purl() != null ? c.purl()
                : (c.path() != null ? c.path().toString() : "?");
        return "[" + c.type() + "] " + (c.groupId() != null ? c.groupId() + ":" : "") + c.name()
                + (c.version() != null ? ":" + c.version() : "") + " (" + identidade + ")";
    }

    private String prefixo(String hash) {
        return hash.substring(0, 12) + "…";
    }
}
