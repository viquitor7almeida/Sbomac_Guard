package dev.sbomguard.ledger;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;

public record LedgerEntry(
        int index,
        String created,
        String keyId,
        String subject,
        String manifestSha256,
        String prevHash,
        String entryHash) {

    private static final ObjectMapper JACKSON = new ObjectMapper()
            .setSerializationInclusion(JsonInclude.Include.NON_NULL);

    public String canonicalJson() throws IOException {
        return JACKSON.writeValueAsString(new LedgerEntry(
                index, created, keyId, subject, manifestSha256, prevHash, null));
    }

    public String toJsonLine() throws IOException {
        return JACKSON.writeValueAsString(this);
    }

    public static LedgerEntry fromJsonLine(String line) throws IOException {
        return JACKSON.readValue(line, LedgerEntry.class);
    }
}
