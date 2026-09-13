package dev.sbomguard.manifest;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.sbomguard.crypto.HashService;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public final class ManifestCodec {

    private final ObjectMapper mapper = new ObjectMapper()
            .setSerializationInclusion(JsonInclude.Include.NON_NULL);

    public String serialize(Manifest manifest) throws IOException {
        return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(manifest);
    }

    public Manifest deserialize(String json) throws IOException {
        return mapper.readValue(json, Manifest.class);
    }

    public String sha256Hex(String manifestJson) {
        return HashService.sha256Hex(manifestJson.getBytes(StandardCharsets.UTF_8));
    }
}
