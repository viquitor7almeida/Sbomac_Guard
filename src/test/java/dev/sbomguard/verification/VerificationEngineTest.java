package dev.sbomguard.verification;

import dev.sbomguard.manifest.Manifest;
import dev.sbomguard.manifest.ManifestBuilder;
import dev.sbomguard.sbom.SbomGenerator;
import dev.sbomguard.scanner.ProjectScanner;
import dev.sbomguard.testkit.Fixtures;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VerificationEngineTest {

    @TempDir
    Path tempDir;

    private final VerificationEngine engine = new VerificationEngine();
    private final Manifest.Tool tool = new Manifest.Tool("sbomguard", "teste");

    private record Atestado(Manifest manifest, Path projeto, Path sbomArquivo) {
    }

    private Atestado atestarCopia(String fixture) throws IOException {
        Path projeto = Fixtures.copy(fixture, tempDir);
        ProjectScanner.ScanResult scan = new ProjectScanner().scan(projeto);
        String sbomJson;
        try {
            sbomJson = new SbomGenerator().toJson(new SbomGenerator().generate(scan,
                    java.util.UUID.nameUUIDFromBytes(fixture.getBytes(StandardCharsets.UTF_8))));
        } catch (Exception e) {
            throw new IOException("falha ao gerar SBOM no teste: " + e.getMessage(), e);
        }
        Path sbomArquivo = projeto.resolve("sbomguard.sbom.json");
        Files.writeString(sbomArquivo, sbomJson);
        Manifest manifest = new ManifestBuilder().build(scan, sbomArquivo, tool);
        return new Atestado(manifest, projeto, sbomArquivo);
    }

    private List<VerificationEngine.Finding> verificar(Atestado atestado) throws IOException {
        ProjectScanner.ScanResult atual = new ProjectScanner().scan(atestado.projeto());
        return engine.verify(atestado.manifest(), atual, atestado.sbomArquivo());
    }

    @Test
    void estadoIdemicoNaoGeraFindings() throws IOException {
        Atestado atestado = atestarCopia("mini-projeto");

        assertTrue(verificar(atestado).isEmpty(), "mesma árvore, mesmo atestado: zero findings");
    }

    @Test
    void alterarUmByteDoPomDoSujeitoGeraHashDivergente() throws IOException {
        Atestado atestado = atestarCopia("mini-projeto");
        Path pom = atestado.projeto().resolve("pom.xml");
        byte[] conteudo = Files.readAllBytes(pom);
        conteudo[5] ^= 0x01;
        Files.write(pom, conteudo);

        List<VerificationEngine.Finding> findings = verificar(atestado);

        assertTrue(findings.stream().anyMatch(f -> f.kind() == VerificationEngine.FindingKind.HASH_DIVERGENTE
                && f.message().contains("sujeito")), "pom do sujeito diverge: " + findings);
    }

    @Test
    void injetarDependenciaNoPomGeraHashDivergenteEInesperado() throws IOException {
        Atestado atestado = atestarCopia("mini-projeto");
        Path pom = atestado.projeto().resolve("pom.xml");
        String original = Files.readString(pom);
        String injetado = original.replace("</dependencies>",
                "  <dependency><groupId>evil.corp</groupId><artifactId>rootkit</artifactId>"
                        + "<version>9.9</version></dependency>\n  </dependencies>");
        Files.writeString(pom, injetado);

        List<VerificationEngine.Finding> findings = verificar(atestado);

        assertTrue(findings.stream().anyMatch(f -> f.kind() == VerificationEngine.FindingKind.HASH_DIVERGENTE),
                "o pom mudou: hash do sujeito deve divergir");
        assertTrue(findings.stream().anyMatch(f -> f.kind() == VerificationEngine.FindingKind.COMPONENTE_INESPERADO
                        && f.message().contains("rootkit")),
                "a dependência injetada deve aparecer como inesperada: " + findings);
    }

    @Test
    void injetarJarNaoAtestadoGeraApenasInesperado() throws IOException {
        Atestado atestado = atestarCopia("mini-projeto");
        Files.createFile(atestado.projeto().resolve("lib/rogue.jar"));

        List<VerificationEngine.Finding> findings = verificar(atestado);

        assertEquals(1, findings.size());
        assertEquals(VerificationEngine.FindingKind.COMPONENTE_INESPERADO, findings.get(0).kind());
        assertTrue(findings.get(0).message().contains("rogue.jar"));
    }

    @Test
    void removerArtefatoAtestadoGeraAusente() throws IOException {
        Atestado atestado = atestarCopia("mini-projeto");
        Files.delete(atestado.projeto().resolve("lib/fake-lib.jar"));

        List<VerificationEngine.Finding> findings = verificar(atestado);

        assertTrue(findings.stream().anyMatch(f -> f.kind() == VerificationEngine.FindingKind.COMPONENTE_AUSENTE
                && f.message().contains("fake-lib.jar")));
    }

    @Test
    void alterarSbomGravadoGeraSbomDivergente() throws IOException {
        Atestado atestado = atestarCopia("mini-projeto");
        byte[] sbom = Files.readAllBytes(atestado.sbomArquivo());
        sbom[9] ^= 0x01;
        Files.write(atestado.sbomArquivo(), sbom);

        List<VerificationEngine.Finding> findings = verificar(atestado);

        assertTrue(findings.stream().anyMatch(f -> f.kind() == VerificationEngine.FindingKind.SBOM_DIVERGENTE));
    }

    @Test
    void apagarSbomGeraSbomAusente() throws IOException {
        Atestado atestado = atestarCopia("mini-projeto");
        Files.delete(atestado.sbomArquivo());

        List<VerificationEngine.Finding> findings = verificar(atestado);

        assertTrue(findings.stream().anyMatch(f -> f.kind() == VerificationEngine.FindingKind.SBOM_AUSENTE));
    }

    @Test
    void alterarVersaoDoPomDeModuloGeraHashDivergente() throws IOException {
        Atestado atestado = atestarCopia("multi-modulo");
        Path pomModulo = atestado.projeto().resolve("mod-a/pom.xml");
        String original = Files.readString(pomModulo);
        Files.writeString(pomModulo, original.replaceFirst(
                "<version>2\\.0\\.0</version>", "<version>2.0.1</version>"));

        List<VerificationEngine.Finding> findings = verificar(atestado);

        assertTrue(findings.stream().anyMatch(f -> f.kind() == VerificationEngine.FindingKind.HASH_DIVERGENTE
                        && f.message().contains("mod-a")),
                "pom de módulo válido mas alterado: hash deve divergir — " + findings);
    }

    @Test
    void pomDeModuloCorrompidoIlegivelGeraComponenteAusente() throws IOException {
        Atestado atestado = atestarCopia("multi-modulo");
        Files.writeString(atestado.projeto().resolve("mod-a/pom.xml"), "<project><quebrado");

        List<VerificationEngine.Finding> findings = verificar(atestado);

        assertTrue(findings.stream().anyMatch(f -> f.kind() == VerificationEngine.FindingKind.COMPONENTE_AUSENTE
                        && f.message().contains("mod-a")),
                "pom ilegível é pulado pelo scanner (F3) e surge como componente ausente — " + findings);
    }
}
