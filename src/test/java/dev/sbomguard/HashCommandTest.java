package dev.sbomguard;

import dev.sbomguard.cli.ExitCodes;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import picocli.CommandLine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HashCommandTest {

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
    void hashImprimeFormatoExatoCompativelComSha256sum() throws Exception {
        Path alvo = tempDir.resolve("alvo.txt");
        Files.writeString(alvo, "abc");

        int exit = newCli().execute("hash", alvo.toString());

        assertEquals(ExitCodes.OK, exit);
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                        + "  " + alvo + System.lineSeparator(),
                stdout.toString());
        assertEquals("", stderr.toString());
    }

    @Test
    void multiplosArquivosContinuaEmFalhaParcial() throws Exception {
        Path bom = tempDir.resolve("bom.txt");
        Files.writeString(bom, "abc");
        Path ausente = tempDir.resolve("ausente.txt");

        int exit = newCli().execute("hash", bom.toString(), ausente.toString());

        assertEquals(ExitCodes.GENERIC_ERROR, exit);
        assertTrue(stdout.toString().startsWith("ba7816bf"));
        assertTrue(stderr.toString().contains(ausente.toString()));
    }

    @Test
    void diretorioNaoEhArquivoRegular() {
        int exit = newCli().execute("hash", tempDir.toString());

        assertEquals(ExitCodes.GENERIC_ERROR, exit);
        assertTrue(stderr.toString().contains("não é um arquivo regular"));
        assertEquals("", stdout.toString());
    }

    @Test
    void semArgumentosEhErroDeUso() {
        int exit = newCli().execute("hash");

        assertEquals(ExitCodes.INVALID_ARGUMENT, exit);
        assertTrue(stderr.toString().contains("Usage: sbomguard hash"));
        assertEquals("", stdout.toString());
    }

    @Test
    void saidaNaoVazaStacktrace() throws Exception {
        Path ausente = tempDir.resolve("sumido.bin");

        int exit = newCli().execute("hash", ausente.toString());

        assertEquals(ExitCodes.GENERIC_ERROR, exit);
        assertFalse(stderr.toString().contains("Exception"));
        assertTrue(stderr.toString().contains(ausente.toString()));
    }

    @Test
    void hashDeArquivoUtf8ComAcentosEhDeterministico() throws Exception {
        Path alvo = tempDir.resolve("acentos.txt");
        Files.writeString(alvo, "integridade é diferente de autenticidade", StandardCharsets.UTF_8);

        int primeiro = newCli().execute("hash", alvo.toString());
        String saida1 = stdout.toString();

        int segundo = newCli().execute("hash", alvo.toString());
        String saida2 = stdout.toString();

        assertEquals(ExitCodes.OK, primeiro);
        assertEquals(ExitCodes.OK, segundo);
        assertEquals(saida1, saida2);
    }
}
