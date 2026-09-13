package dev.sbomguard.ledger;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.Base64;

public record Anchor(String ledgerHead, int entryCount, String created, String keyId, String signatureBase64) {

    private static final ObjectMapper JACKSON = new ObjectMapper()
            .setSerializationInclusion(JsonInclude.Include.NON_NULL);

    public String canonicalJson() throws IOException {
        return JACKSON.writeValueAsString(new Anchor(ledgerHead, entryCount, created, keyId, null));
    }

    public String serialize() throws IOException {
        return JACKSON.writeValueAsString(this);
    }

    public static Anchor deserialize(String json) throws IOException {
        return JACKSON.readValue(json, Anchor.class);
    }

    public byte[] signatureBytes() {
        return Base64.getDecoder().decode(signatureBase64);
    }
}
