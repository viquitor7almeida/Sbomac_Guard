package dev.sbomguard.ledger;

import dev.sbomguard.crypto.HashService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LedgerServiceTest {

    @TempDir
    Path tempDir;

    private final LedgerService service = new LedgerService();

    private Path novoLedger() {
        return tempDir.resolve("ledger.jsonl");
    }

    @Test
    void primeiraEntradaAncoraNaGenesisEOHashDoNada() throws IOException {
        Path ledger = novoLedger();

        LedgerService.AppendResult r = service.append(ledger, "chave-a", "g:a:1", "hash-manifesto-1");

        assertEquals(1, r.index());
        LedgerEntry entrada = service.readAll(ledger).get(0);
        assertEquals(LedgerService.GENESIS, entrada.prevHash(),
                "gênese é o SHA-256 do vazio — verificável por qualquer um");
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                LedgerService.GENESIS);
        assertEquals(HashService.sha256Hex(entrada.canonicalJson().getBytes(StandardCharsets.UTF_8)),
                entrada.entryHash(), "entryHash é o hash da forma canônica");
    }

    @Test
    void segundaEntradaEncadeiaComAPrimeira() throws IOException {
        Path ledger = novoLedger();
        service.append(ledger, "chave-a", "g:a:1", "hash-1");
        LedgerService.AppendResult r2 = service.append(ledger, "chave-a", "g:a:2", "hash-2");

        List<LedgerEntry> entries = service.readAll(ledger);
        assertEquals(2, entries.size());
        assertEquals(2, r2.index());
        assertEquals(entries.get(0).entryHash(), entries.get(1).prevHash(),
                "encadeamento: prevHash da 2ª = entryHash da 1ª");
    }

    @Test
    void cadeiaIntactaVerificaSemProblemas() throws IOException {
        Path ledger = novoLedger();
        service.append(ledger, "chave-a", "g:a:1", "hash-1");
        service.append(ledger, "chave-b", "g:a:2", "hash-2");
        service.append(ledger, "chave-a", "g:a:3", "hash-3");

        LedgerService.ChainVerification v = service.verifyChain(ledger);

        assertTrue(v.intact(), () -> "problemas inesperados: " + v.problems());
    }

    @Test
    void adulterarCampoDaEntradaQuebraCadeiaDaliEmDiante() throws IOException {
        Path ledger = novoLedger();
        service.append(ledger, "chave-a", "g:a:1", "hash-1");
        service.append(ledger, "chave-a", "g:a:2", "hash-2");

        List<String> linhas = Files.readAllLines(ledger, StandardCharsets.UTF_8);
        linhas.set(0, linhas.get(0).replace("g:a:1", "g:FALSO:1"));
        Files.write(ledger, linhas, StandardCharsets.UTF_8);

        LedgerService.ChainVerification v = service.verifyChain(ledger);

        assertFalse(v.intact());
        assertTrue(v.problems().stream().anyMatch(p -> p.contains("#1") && p.contains("recalculado")),
                "a entrada adulterada denuncia a si mesma: " + v.problems());
        assertTrue(v.problems().stream().anyMatch(p -> p.contains("#2") && p.contains("encadeia")),
                "e a seguinte denuncia o rompimento: " + v.problems());
    }

    @Test
    void removerEntradaIntermediariaQuebraEncadeamento() throws IOException {
        Path ledger = novoLedger();
        service.append(ledger, "chave-a", "g:a:1", "hash-1");
        service.append(ledger, "chave-a", "g:a:2", "hash-2");
        service.append(ledger, "chave-a", "g:a:3", "hash-3");

        List<String> linhas = Files.readAllLines(ledger, StandardCharsets.UTF_8);
        linhas.remove(1);
        Files.write(ledger, linhas, StandardCharsets.UTF_8);

        LedgerService.ChainVerification v = service.verifyChain(ledger);

        assertFalse(v.intact());
        assertTrue(v.problems().stream().anyMatch(p -> p.contains("encadeia")));
    }

    @Test
    void reordenarEntradasQuebraEncadeamento() throws IOException {
        Path ledger = novoLedger();
        service.append(ledger, "chave-a", "g:a:1", "hash-1");
        service.append(ledger, "chave-a", "g:a:2", "hash-2");

        List<String> linhas = Files.readAllLines(ledger, StandardCharsets.UTF_8);
        java.util.Collections.swap(linhas, 0, 1);
        Files.write(ledger, linhas, StandardCharsets.UTF_8);

        assertFalse(service.verifyChain(ledger).intact());
    }

    @Test
    void linhaLixoNoMeioEhProblemaNaoCrash() throws IOException {
        Path ledger = novoLedger();
        service.append(ledger, "chave-a", "g:a:1", "hash-1");

        List<String> linhas = Files.readAllLines(ledger, StandardCharsets.UTF_8);
        linhas.add("isto não é json");
        Files.write(ledger, linhas, StandardCharsets.UTF_8);

        LedgerService.ChainVerification v = service.verifyChain(ledger);

        assertFalse(v.intact());
        assertTrue(v.problems().stream().anyMatch(p -> p.contains("ilegível")));
    }

    @Test
    void appendRecusaEstenderCadeiaQuebrada() throws IOException {
        Path ledger = novoLedger();
        service.append(ledger, "chave-a", "g:a:1", "hash-1");
        List<String> linhas = Files.readAllLines(ledger, StandardCharsets.UTF_8);
        Files.write(ledger, List.of(linhas.get(0).replace("g:a:1", "g:FALSO")),
                StandardCharsets.UTF_8);

        IOException e = org.junit.jupiter.api.Assertions.assertThrows(IOException.class,
                () -> service.append(ledger, "chave-a", "g:a:2", "hash-2"));

        assertTrue(e.getMessage().contains("recusa em anexar"),
                "anexar sobre ledger adulterado legitimiria o estado anterior: " + e.getMessage());
    }

    @Test
    void roundTripCanonicoEhEstavelEmBytes() throws IOException {
        Path ledger = novoLedger();
        service.append(ledger, "chave-a", "g:a:1", "hash-1");
        LedgerEntry entrada = service.readAll(ledger).get(0);

        String canonico1 = entrada.canonicalJson();
        LedgerEntry relida = LedgerEntry.fromJsonLine(entrada.toJsonLine());
        String canonico2 = relida.canonicalJson();

        assertEquals(canonico1, canonico2,
                "forma canônica deve ser re-derivável byte a byte (a verificação depende disso)");
    }

    @Test
    void reescritaTotalDaCadeiaNaoEhDetectavelPelaCadeiaSozinha() throws IOException {
        Path ledger = novoLedger();
        service.append(ledger, "chave-a", "g:a:1", "hash-1");
        service.append(ledger, "chave-a", "g:a:2", "hash-2");

        List<LedgerEntry> originais = service.readAll(ledger);
        StringBuilder falsario = new StringBuilder();
        String prev = LedgerService.GENESIS;
        int indice = 1;
        for (LedgerEntry original : originais) {
            LedgerEntry adulterada = new LedgerEntry(indice, original.created(), original.keyId(),
                    "falso:sujeito", original.manifestSha256(), prev, null);
            String hash = HashService.sha256Hex(adulterada.canonicalJson().getBytes(StandardCharsets.UTF_8));
            falsario.append(new LedgerEntry(indice, adulterada.created(), adulterada.keyId(),
                    adulterada.subject(), adulterada.manifestSha256(), prev, hash).toJsonLine())
                    .append(System.lineSeparator());
            prev = hash;
            indice++;
        }
        Files.writeString(ledger, falsario.toString());

        assertTrue(service.verifyChain(ledger).intact(),
                "LIMITAÇÃO PINADA: reescrita total com hashes recalculados passa — "
                        + "é exatamente por isso que a âncora externa (F10) existe");
    }

    @Test
    void ledgerInexistenteLidoComoVazio() throws IOException {
        assertTrue(service.readAll(tempDir.resolve("nao-existe.jsonl")).isEmpty());
        assertTrue(service.verifyChain(tempDir.resolve("nao-existe.jsonl")).intact());
    }
}
