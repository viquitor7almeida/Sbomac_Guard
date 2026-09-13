package dev.sbomguard.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.sbomguard.crypto.HashService;
import dev.sbomguard.scanner.ProjectScanner;
import dev.sbomguard.testkit.Fixtures;
import org.cyclonedx.exception.ParseException;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SbomGeneratorTest {

    private final ObjectMapper jackson = new ObjectMapper();
    private final SbomGenerator generator = new SbomGenerator();
    private final UUID serialFixo = UUID.nameUUIDFromBytes("sbomguard-teste".getBytes(StandardCharsets.UTF_8));

    private ProjectScanner.ScanResult scan(String fixture) throws IOException {
        return new ProjectScanner().scan(Fixtures.path(fixture));
    }

    private String sbomJson(String fixture) throws Exception {
        return generator.toJson(generator.generate(scan(fixture), serialFixo));
    }

    @Test
    void sbomDoMiniProjetoPassaNaValidacaoDeSchema() throws Exception {
        String json = sbomJson("mini-projeto");
        List<ParseException> erros = generator.validate(json);

        assertTrue(erros.isEmpty(), "schema CycloneDX rejeitou o SBOM gerado: " + erros);

        JsonNode root = jackson.readTree(json);
        assertEquals("CycloneDX", root.get("bomFormat").asText());
        assertEquals("1.6", root.get("specVersion").asText());
        assertTrue(root.get("serialNumber").asText().startsWith("urn:uuid:"));
    }

    @Test
    void sujeitoDoSbomEhOPomRaizEComponentsTemODemais() throws Exception {
        JsonNode root = jackson.readTree(sbomJson("mini-projeto"));

        JsonNode subject = root.get("metadata").get("component");
        assertEquals("com.exemplo.demo", subject.get("group").asText());
        assertEquals("app", subject.get("name").asText());
        assertEquals("1.2.3", subject.get("version").asText());

        assertEquals(5, root.get("components").size(), "4 dependências + 1 jar (pom raiz é o sujeito)");
    }

    @Test
    void hashDoArtefatoConfereComHashServiceDaFase2() throws Exception {
        JsonNode root = jackson.readTree(sbomJson("mini-projeto"));

        JsonNode jar = componentePor(root, "file", "fake-lib.jar");
        JsonNode hash = jar.get("hashes").get(0);
        assertEquals("SHA-256", hash.get("alg").asText());
        assertEquals(HashService.sha256Hex(Fixtures.path("mini-projeto/lib/fake-lib.jar")),
                hash.get("content").asText(), "hash no SBOM deve ser o mesmo medido pelo HashService");
        assertNull(jar.get("purl"), "arquivo não tem purl — não inventamos");
    }

    @Test
    void escoposMavenMapeiamParaSemanticaCycloneDx() throws Exception {
        JsonNode root = jackson.readTree(sbomJson("mini-projeto"));

        assertEquals("excluded", componentePor(root, "library", "junit-jupiter").get("scope").asText(),
                "dependência de teste não embarca no artefato");
        assertEquals("optional", componentePor(root, "library", "jackson-databind").get("scope").asText(),
                "provided é fornecido pelo ambiente");
        assertEquals("required", componentePor(root, "library", "picocli").get("scope").asText());
    }

    @Test
    void dependenciaSemVersaoResolvidaFicaSemVersaoNoSbom() throws Exception {
        JsonNode root = jackson.readTree(sbomJson("mini-projeto"));

        JsonNode junit = componentePor(root, "library", "junit-jupiter");
        assertEquals("pkg:maven/org.junit.jupiter/junit-jupiter", junit.get("purl").asText());
        assertNull(junit.get("version"), "versão por propriedade não resolvida não vira dado fabricado");
    }

    @Test
    void multiModuloRaizEhSujeitoEModulosFicamEmComponents() throws Exception {
        JsonNode root = jackson.readTree(sbomJson("multi-modulo"));

        assertEquals("multi", root.get("metadata").get("component").get("name").asText());
        assertEquals(4, root.get("components").size(), "2 módulos + picocli + jackson");
        assertEquals("application", componentePor(root, "application", "mod-a").get("type").asText());
    }

    @Test
    void semPomGeraSbomSemMetadataMasValido() throws Exception {
        String json = sbomJson("sem-pom");

        assertTrue(generator.validate(json).isEmpty());
        JsonNode root = jackson.readTree(json);
        assertNull(root.get("metadata"));
        assertEquals(1, root.get("components").size());
        assertEquals("file", root.get("components").get(0).get("type").asText());
    }

    @Test
    void determinismoMesmoSerialRemoveTimestampIgualaJsonAnterior() throws Exception {
        String json1 = sbomJson("mini-projeto");
        String json2 = sbomJson("mini-projeto");

        ObjectNode n1 = (ObjectNode) jackson.readTree(json1);
        ObjectNode n2 = (ObjectNode) jackson.readTree(json2);
        ((ObjectNode) n1.get("metadata")).remove("timestamp");
        ((ObjectNode) n2.get("metadata")).remove("timestamp");

        assertEquals(n1.toString(), n2.toString(), "com mesmo serial e sem timestamp, geração é determinística");
    }

    private JsonNode componentePor(JsonNode root, String tipo, String nome) {
        for (JsonNode c : root.get("components")) {
            if (tipo.equals(c.get("type").asText()) && nome.equals(c.get("name").asText())) {
                return c;
            }
        }
        throw new AssertionError("componente não encontrado: type=" + tipo + " name=" + nome);
    }
}
