package dev.sbomguard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.sbomguard.cli.ExitCodes;
import dev.sbomguard.sbom.SbomGenerator;
import dev.sbomguard.testkit.Fixtures;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SbomCommandTest {

    private final ObjectMapper jackson = new ObjectMapper();

    @TempDir
    Path tempDir;

    private StringWriter stdout;
    private StringWriter stderr;

    private CommandLine newCli() {
        stdout = new StringWriter();
        stderr = new StringWriter();
        return SbomGuardCli.configuredCommandLine()
                .setOut(new PrintWriter(stdout, true))
                .setErr(new PrintWriter(stderr, true));
    }

    @Test
    void sbomEmStdoutEJsonValidoComAvisosFora() throws Exception {
        int exit = newCli().execute("sbom", Fixtures.path("mini-projeto").toString());

        assertEquals(ExitCodes.OK, exit);
        JsonNode root = jackson.readTree(stdout.toString());
        assertEquals("CycloneDX", root.get("bomFormat").asText());
        assertEquals(5, root.get("components").size());
        assertEquals("", stderr.toString(), "stdout deve ser JSON puro, avisos vão para stderr");
    }

    @Test
    void sbomComOutputEscreveArquivoValidoEmSilencio() throws Exception {
        Path arquivo = tempDir.resolve("sbom.json");

        int exit = newCli().execute("sbom", Fixtures.path("mini-projeto").toString(),
                "--output", arquivo.toString());

        assertEquals(ExitCodes.OK, exit);
        assertEquals("", stdout.toString(), "sucesso escrevendo arquivo deve ser silencioso (unix)");
        String json = Files.readString(arquivo);
        assertTrue(new SbomGenerator().validate(json).isEmpty(), "arquivo escrito deve validar");
        assertEquals(5, jackson.readTree(json).get("components").size());
    }

    @Test
    void sbomSemPomGeraSbomDeArquivosComAviso() throws Exception {
        int exit = newCli().execute("sbom", Fixtures.path("sem-pom").toString());

        assertEquals(ExitCodes.OK, exit);
        assertEquals(1, jackson.readTree(stdout.toString()).get("components").size());
        assertTrue(stderr.toString().contains("nenhum pom.xml"));
    }

    @Test
    void sbomDiretorioInexistenteSaiComUm() {
        int exit = newCli().execute("sbom", "/caminho/que/nao/existe");

        assertEquals(ExitCodes.GENERIC_ERROR, exit);
        assertTrue(stderr.toString().contains("não é um diretório"));
    }

    @Test
    void sbomOutputEmDiretorioInexistenteSaiComUm() {
        int exit = newCli().execute("sbom", Fixtures.path("mini-projeto").toString(),
                "--output", "/caminho/que/nao/existe/sbom.json");

        assertEquals(ExitCodes.GENERIC_ERROR, exit);
        assertTrue(stderr.toString().contains("diretório de saída inexistente"));
    }
}
