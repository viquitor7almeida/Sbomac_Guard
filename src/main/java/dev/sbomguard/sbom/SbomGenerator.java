package dev.sbomguard.sbom;

import dev.sbomguard.crypto.HashService;
import dev.sbomguard.scanner.Component;
import dev.sbomguard.scanner.ProjectScanner.ScanResult;
import org.cyclonedx.Version;
import org.cyclonedx.exception.GeneratorException;
import org.cyclonedx.exception.ParseException;
import org.cyclonedx.generators.BomGeneratorFactory;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component.Scope;
import org.cyclonedx.model.Component.Type;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.parsers.JsonParser;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * Materializa um ScanResult como SBOM CycloneDX (JSON), spec 1.6.
 *
 * Regras de honestidade:
 * - hash SHA-256 SOMENTE em artefatos de arquivo medidos localmente (HashService,
 *   F2); dependência declarada nunca recebe hash inventado;
 * - sem grafo de dependências fabricado (declarado ≠ resolvido — limitação MVP);
 * - serialNumber/timestamp carregam PROVENIÊNCIA (quando/por qual instância foi
 *   gerado): propositalmente variam por execução. Reprodutibilidade de
 *   VERIFICAÇÃO vem do manifesto (F5) comparar o hash do ARQUIVO gerado, não de
 *   regenerar.
 *
 * O sujeito do SBOM (metadata.component) é o pom da raiz; na ausência dele,
 * o primeiro pom por ordem de caminho; sem nenhum pom, sem metadata.
 * O sujeito não se repete na lista de components (convenção CycloneDX).
 */
public final class SbomGenerator {

    /** 1.6: compatibilidade ampla de consumidores (1.7 disponível na lib se quisermos). */
    public static final Version SPEC_VERSION = Version.VERSION_16;

    public Bom generate(ScanResult scan, UUID serialNumber) throws IOException {
        Component subject = subjectOrNull(scan);

        Bom bom = new Bom();
        bom.setSerialNumber("urn:uuid:" + serialNumber);
        if (subject != null) {
            Metadata metadata = new Metadata();
            metadata.setTimestamp(new Date());
            metadata.setComponent(toCycloneDx(subject, scan));
            bom.setMetadata(metadata);
        }
        for (Component c : scan.components()) {
            if (c.equals(subject)) {
                continue;
            }
            bom.addComponent(toCycloneDx(c, scan));
        }
        return bom;
    }

    public String toJson(Bom bom) throws GeneratorException {
        return BomGeneratorFactory.createJson(SPEC_VERSION, bom).toJsonString();
    }

    /** Valida contra o schema oficial CycloneDX embutido na lib. Vazio = válido. */
    public List<ParseException> validate(String json) throws IOException {
        return new JsonParser().validate(json.getBytes(StandardCharsets.UTF_8), SPEC_VERSION);
    }

    private Component subjectOrNull(ScanResult scan) {
        return scan.components().stream()
                .filter(c -> c.type() == Component.ComponentType.PROJECT_POM)
                .filter(c -> c.path() != null && c.path().getNameCount() == 1)
                .findFirst()
                .orElseGet(() -> scan.components().stream()
                        .filter(c -> c.type() == Component.ComponentType.PROJECT_POM)
                        .findFirst()
                        .orElse(null));
    }

    private org.cyclonedx.model.Component toCycloneDx(Component c, ScanResult scan) throws IOException {
        org.cyclonedx.model.Component out = new org.cyclonedx.model.Component();
        switch (c.type()) {
            case PROJECT_POM -> {
                out.setType(Type.APPLICATION);
                out.setGroup(c.groupId());
                out.setName(c.name());
                out.setVersion(versaoEfetiva(c.version()));
                if (c.purl() != null) {
                    out.setPurl(c.purl());
                }
            }
            case MAVEN_DEPENDENCY -> {
                out.setType(Type.LIBRARY);
                out.setGroup(c.groupId());
                out.setName(c.name());
                out.setVersion(versaoEfetiva(c.version()));
                out.setPurl(c.purl());
                out.setScope(escopoMavenParaCycloneDx(c.scope()));
            }
            case FILE_ARTIFACT -> {
                out.setType(Type.FILE);
                out.setName(c.name());
                out.addHash(new Hash(Hash.Algorithm.SHA_256,
                        HashService.sha256Hex(scan.root().resolve(c.path()))));
            }
        }
        return out;
    }

    private Scope escopoMavenParaCycloneDx(String mavenScope) {
        return switch (mavenScope == null ? "compile" : mavenScope) {
            case "test" -> Scope.EXCLUDED;
            case "provided", "system" -> Scope.OPTIONAL;
            default -> Scope.REQUIRED;
        };
    }

    /** Placeholder de propriedade (${...}) não é versão: o SBOM omite em vez de propagar ruído. */
    private String versaoEfetiva(String version) {
        return (version == null || version.isBlank() || version.startsWith("${")) ? null : version;
    }
}
