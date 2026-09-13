package dev.sbomguard.manifest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.sbomguard.crypto.HashService;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ManifestCodecTest {

    private final ManifestCodec codec = new ManifestCodec();
    private final ObjectMapper jackson = new ObjectMapper();

    private Manifest manifestoExemplo() {
        ManifestComponent jar = new ManifestComponent(
                ManifestComponent.TYPE_FILE_ARTIFACT, null, "fake-lib.jar", null, null, null,
                "lib/fake-lib.jar", "a".repeat(64));
        ManifestComponent dep = new ManifestComponent(
                ManifestComponent.TYPE_MAVEN_DEPENDENCY, "info.picocli", "picocli", "4.7.7",
                "compile", "pkg:maven/info.picocli/picocli@4.7.7", null, null);
        return new Manifest(
                1,
                "2026-09-13T18:00:00Z",
                new Manifest.Tool("sbomguard", "0.1.0-SNAPSHOT"),
                new Manifest.Subject("com.exemplo.demo", "app", "1.2.3",
                        "pkg:maven/com.exemplo.demo/app@1.2.3", "pom.xml", "b".repeat(64)),
                new Manifest.SbomRef("sbomguard.sbom.json", "c".repeat(64)),
                List.of(dep, jar));
    }

    @Test
    void roundTripPreservaIdentidadeDoManifesto() throws IOException {
        Manifest original = manifestoExemplo();

        Manifest lido = codec.deserialize(codec.serialize(original));

        assertEquals(original, lido, "records imutáveis: desserialização deve produzir igualdade total");
    }

    @Test
    void roundTripEhByteAByte() throws IOException {
        String json1 = codec.serialize(manifestoExemplo());

        String json2 = codec.serialize(codec.deserialize(json1));

        assertEquals(json1, json2, "serializar→desserializar→serializar deve ser estável em bytes (F6 assinará bytes)");
    }

    @Test
    void campoNaoMedidoFicaAusenteNoJson() throws IOException {
        JsonNode root = jackson.readTree(codec.serialize(manifestoExemplo()));

        JsonNode picocli = componenteChamado(root, "picocli");
        JsonNode jar = componenteChamado(root, "fake-lib.jar");

        assertFalse(picocli.has("sha256"), "dependência sem hash não pode exibir campo sha256");
        assertFalse(picocli.has("path"), "dependência declarada não tem path");
        assertTrue(jar.has("sha256"), "artefato medido deve exibir sha256");
    }

    @Test
    void desserializacaoRejeitaCampoDesconhecido() throws IOException {
        String json = codec.serialize(manifestoExemplo()).replaceFirst("\\{",
                "{\"campo-malicioso\": 1,");

        assertThrows(IOException.class, () -> codec.deserialize(json),
                "manifesto adulterado com campo estranho deve ser rejeitado (strict typing)");
    }

    @Test
    void desserializacaoRejeitaJsonLixo() {
        assertThrows(IOException.class, () -> codec.deserialize("isto não é json"));
    }

    @Test
    void hashDoCodecConfereComHashService() throws IOException {
        String json = codec.serialize(manifestoExemplo());

        assertEquals(HashService.sha256Hex(json.getBytes(StandardCharsets.UTF_8)), codec.sha256Hex(json));
    }

    private JsonNode componenteChamado(JsonNode root, String nome) {
        for (JsonNode c : root.get("components")) {
            if (nome.equals(c.get("name").asText())) {
                return c;
            }
        }
        throw new AssertionError("componente não encontrado: " + nome);
    }
}
