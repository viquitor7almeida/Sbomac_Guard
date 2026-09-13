package dev.sbomguard;

import dev.sbomguard.cli.ExitCodes;
import dev.sbomguard.crypto.HashService;
import dev.sbomguard.manifest.Manifest;
import dev.sbomguard.manifest.ManifestCodec;
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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AttestCommandTest {

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
    void attestGravaSbomValidoEManifestoConsistente() throws Exception {
        Path saida = tempDir.resolve("out");

        int exit = newCli().execute("attest", Fixtures.path("mini-projeto").toString(),
                "--output-dir", saida.toString());

        assertEquals(ExitCodes.OK, exit);

        Path sbomPath = saida.resolve("sbomguard.sbom.json");
        Path manifestPath = saida.resolve("sbomguard.manifest.json");
        assertTrue(Files.isRegularFile(sbomPath));
        assertTrue(Files.isRegularFile(manifestPath));

        String sbomJson = Files.readString(sbomPath);
        assertTrue(new SbomGenerator().validate(sbomJson).isEmpty(), "SBOM gravado deve validar");

        Manifest manifest = new ManifestCodec().deserialize(Files.readString(manifestPath));
        assertEquals("app", manifest.subject().name());
        assertEquals(HashService.sha256Hex(sbomPath), manifest.sbom().sha256(),
                "âncora: hash do SBOM gravado deve bater com o registrado no manifesto");
    }

    @Test
    void resumoExibeHashCompletoDoManifesto() throws Exception {
        int exit = newCli().execute("attest", Fixtures.path("mini-projeto").toString(),
                "--output-dir", tempDir.toString());

        assertEquals(ExitCodes.OK, exit);
        String out = stdout.toString();
        assertTrue(out.contains("sujeito: com.exemplo.demo:app:1.2.3"));
        assertTrue(java.util.regex.Pattern.compile("sha256 do manifesto: [0-9a-f]{64}").matcher(out).find(),
                "resumo deve trazer o hash de 64 hex — a âncora para F6/F8");
        Path manifestPath = tempDir.resolve("sbomguard.manifest.json");
        String hashEsperado = new ManifestCodec().sha256Hex(Files.readString(manifestPath));
        assertTrue(out.contains(hashEsperado), "hash impresso deve ser o do arquivo gravado");
    }

    @Test
    void alterarUmByteDoSbomQuebraAAncoraDoManifesto() throws Exception {
        Path saida = tempDir.resolve("out");
        newCli().execute("attest", Fixtures.path("mini-projeto").toString(),
                "--output-dir", saida.toString());

        Path sbomPath = saida.resolve("sbomguard.sbom.json");
        Manifest manifest = new ManifestCodec().deserialize(
                Files.readString(saida.resolve("sbomguard.manifest.json")));
        assertEquals(manifest.sbom().sha256(), HashService.sha256Hex(sbomPath),
                "âncora íntegra antes do ataque");

        byte[] conteudo = Files.readAllBytes(sbomPath);
        conteudo[10] ^= 0x01;
        Files.write(sbomPath, conteudo);

        assertNotEquals(manifest.sbom().sha256(), HashService.sha256Hex(sbomPath),
                "1 byte alterado no SBOM deve invalidar a âncora — é isto que a F7 verificará");
    }

    @Test
    void attestSemPomGeraAtestadoDeArquivos() throws Exception {
        int exit = newCli().execute("attest", Fixtures.path("sem-pom").toString(),
                "--output-dir", tempDir.toString());

        assertEquals(ExitCodes.OK, exit);
        Manifest manifest = new ManifestCodec().deserialize(
                Files.readString(tempDir.resolve("sbomguard.manifest.json")));
        assertNull(manifest.subject());
        assertEquals(1, manifest.components().size());
        assertTrue(stderr.toString().contains("nenhum pom.xml"));
    }

    @Test
    void attestDiretorioInexistenteSaiComUm() {
        int exit = newCli().execute("attest", "/caminho/que/nao/existe");

        assertEquals(ExitCodes.GENERIC_ERROR, exit);
        assertTrue(stderr.toString().contains("não é um diretório"));
    }

    @Test
    void outputDirAninhadoEhCriado() throws Exception {
        Path saida = tempDir.resolve("a/b/c");

        int exit = newCli().execute("attest", Fixtures.path("sem-pom").toString(),
                "--output-dir", saida.toString());

        assertEquals(ExitCodes.OK, exit);
        assertTrue(Files.isRegularFile(saida.resolve("sbomguard.manifest.json")),
                "diretório de saída aninhado deve ser criado");
    }
}
