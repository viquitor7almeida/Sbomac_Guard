package dev.sbomguard.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.Base64;

public record SignatureEnvelope(String algorithm, String keyId, String signatureBase64) {

    public static final String ALGORITHM_ED25519 = "Ed25519";

    private static final ObjectMapper JACKSON = new ObjectMapper();

    public static SignatureEnvelope ofEd25519(String keyFingerprint, byte[] signature) {
        return new SignatureEnvelope(ALGORITHM_ED25519, keyFingerprint,
                Base64.getEncoder().encodeToString(signature));
    }

    public byte[] signatureBytes() {
        return Base64.getDecoder().decode(signatureBase64);
    }

    public String serialize() throws IOException {
        return JACKSON.writeValueAsString(this);
    }

    public static SignatureEnvelope deserialize(String json) throws IOException {
        return JACKSON.readValue(json, SignatureEnvelope.class);
    }
}
