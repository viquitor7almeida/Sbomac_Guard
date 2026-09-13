package dev.sbomguard;

import dev.sbomguard.cli.ExitCodes;
import dev.sbomguard.crypto.KeyService;
import dev.sbomguard.ledger.Anchor;
import dev.sbomguard.ledger.LedgerService;
import dev.sbomguard.testkit.Fixtures;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AnchorCommandTest {

    @TempDir
    Path tempDir;

    private Path projeto;
    private Path ledger;
    private Path chavePrivada;
    private Path chavePublica;

    private StringWriter stdout;
    private StringWriter stderr;

    private CommandLine newCli() {
        stdout = new StringWriter();
        stderr = new StringWriter();
        return SbomGuardCli.configuredCommandLine()
                .setOut(new PrintWriter(stdout, true))
                .setErr(new PrintWriter(stderr, true));
    }

    @BeforeEach
    void preparaProjetoComLedger() throws IOException {
        KeyService.GeneratedKeys chaves = new KeyService().generateAndSave(tempDir.resolve("keys"));
        chavePrivada = chaves.privateKeyFile();
        chavePublica = chaves.publicKeyFile();

        projeto = Fixtures.copy("mini-projeto", tempDir);
        assertEquals(ExitCodes.OK, newCli().execute("attest", projeto.toString()));
        Path manifesto = projeto.resolve("sbomguard.manifest.json");
        assertEquals(ExitCodes.OK, newCli().execute("sign", manifesto.toString(),
                "--key", chavePrivada.toString()));
        ledger = projeto.resolve(LedgerService.LEDGER_FILE);
    }

    @Test
    void anchorCriaCheckpointAssinadoComInstrucaoDePublicacao() throws IOException {
        int exit = newCli().execute("anchor", projeto.toString(), "--key", chavePrivada.toString());

        assertEquals(ExitCodes.OK, exit);
        Path ancora = projeto.resolve("sbomguard.anchor.json");
        assertTrue(Files.isRegularFile(ancora));
        Anchor gravada = Anchor.deserialize(Files.readString(ancora, StandardCharsets.UTF_8));
        assertEquals(1, gravada.entryCount());
        assertTrue(stdout.toString().contains("publique-a FORA"),
                "o comando ensina: âncora que o atacante reescreve não ancora nada");
    }

    @Test
    void anchorLedgerInexistenteErroUm() {
        int exit = newCli().execute("anchor", tempDir.resolve("nada").toString(),
                "--key", chavePrivada.toString());

        assertEquals(ExitCodes.GENERIC_ERROR, exit);
        assertTrue(stderr.toString().contains("nada a ancorar"));
    }

    @Test
    void anchorRecusaLedgerAdulterado() throws IOException {
        List<String> linhas = Files.readAllLines(ledger, StandardCharsets.UTF_8);
        Files.write(ledger, List.of(linhas.get(0).replace("com.exemplo.demo", "evil.corp")),
                StandardCharsets.UTF_8);

        int exit = newCli().execute("anchor", projeto.toString(), "--key", chavePrivada.toString());

        assertEquals(ExitCodes.GENERIC_ERROR, exit, "não se ancora mentira");
        assertTrue(stderr.toString().contains("recusa em ancorar"));
    }
}
