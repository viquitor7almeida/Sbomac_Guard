package dev.sbomguard.ledger;

import dev.sbomguard.crypto.HashService;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public final class LedgerService {

    public static final String LEDGER_FILE = "sbomguard.ledger.jsonl";

    public static final String GENESIS = HashService.sha256Hex(new byte[0]);

    public record AppendResult(int index, String entryHash) {
    }

    public record ChainVerification(boolean intact, List<String> problems) {
    }

    public AppendResult append(Path ledgerFile, String keyId, String subject, String manifestSha256)
            throws IOException {
        ChainVerification estado = verifyChain(ledgerFile);
        if (!estado.intact()) {
            throw new IOException("ledger adulterado — recusa em anexar: " + estado.problems().get(0));
        }
        if (ledgerFile.getParent() != null) {
            Files.createDirectories(ledgerFile.getParent());
        }
        List<LedgerEntry> entries = readAll(ledgerFile);
        String prevHash = entries.isEmpty() ? GENESIS : entries.get(entries.size() - 1).entryHash();
        int index = entries.size() + 1;

        LedgerEntry base = new LedgerEntry(index, Instant.now().toString(),
                keyId, subject, manifestSha256, prevHash, null);
        String entryHash = HashService.sha256Hex(base.canonicalJson().getBytes(StandardCharsets.UTF_8));
        LedgerEntry completa = new LedgerEntry(index, base.created(), keyId, subject,
                manifestSha256, prevHash, entryHash);

        try (BufferedWriter w = Files.newBufferedWriter(ledgerFile, StandardCharsets.UTF_8,
                java.nio.file.StandardOpenOption.CREATE,
                java.nio.file.StandardOpenOption.APPEND)) {
            w.write(completa.toJsonLine());
            w.newLine();
        }
        return new AppendResult(index, entryHash);
    }

    public List<LedgerEntry> readAll(Path ledgerFile) throws IOException {
        if (!Files.isRegularFile(ledgerFile)) {
            return List.of();
        }
        List<LedgerEntry> entries = new ArrayList<>();
        List<String> lines = Files.readAllLines(ledgerFile, StandardCharsets.UTF_8);
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            if (line.isBlank()) {
                throw new IOException("linha " + (i + 1) + " vazia — append-only não produz linhas vazias");
            }
            try {
                entries.add(LedgerEntry.fromJsonLine(line));
            } catch (IOException e) {
                throw new IOException("linha " + (i + 1) + " ilegível: " + e.getMessage(), e);
            }
        }
        return List.copyOf(entries);
    }

    public ChainVerification verifyChain(Path ledgerFile) throws IOException {
        if (!Files.isRegularFile(ledgerFile)) {
            return new ChainVerification(true, List.of());
        }
        List<String> problems = new ArrayList<>();
        List<String> lines = Files.readAllLines(ledgerFile, StandardCharsets.UTF_8);

        String prevHash = GENESIS;
        int expectedIndex = 1;
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            int numeroLinha = i + 1;
            if (line.isBlank()) {
                problems.add("linha " + numeroLinha + ": vazia (append-only não produz linhas vazias)");
                prevHash = null;
                continue;
            }
            LedgerEntry entry;
            try {
                entry = LedgerEntry.fromJsonLine(line);
            } catch (IOException e) {
                problems.add("linha " + numeroLinha + ": ilegível — " + e.getMessage());
                prevHash = null;
                continue;
            }
            if (entry.index() != expectedIndex) {
                problems.add("entrada da linha " + numeroLinha + ": índice " + entry.index()
                        + " onde esperava " + expectedIndex);
            }
            String recalculado = HashService.sha256Hex(
                    entry.canonicalJson().getBytes(StandardCharsets.UTF_8));
            if (entry.entryHash() == null || !entry.entryHash().equals(recalculado)) {
                problems.add("entrada #" + entry.index() + ": hash recalculado diverge do registrado");
            }
            if (entry.prevHash() == null || !entry.prevHash().equals(prevHash)) {
                problems.add("entrada #" + entry.index() + ": prevHash não encadeia com a anterior");
            }

            prevHash = recalculado;
            expectedIndex++;
        }
        return new ChainVerification(problems.isEmpty(), List.copyOf(problems));
    }
}
