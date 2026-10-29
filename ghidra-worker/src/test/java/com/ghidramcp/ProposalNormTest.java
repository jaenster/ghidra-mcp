package com.ghidramcp;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** ProposalNorm against the vectors the Redivivus proposal checker produced. */
class ProposalNormTest {
    private static JsonObject vectors;

    @BeforeAll
    static void load() throws Exception {
        String path = System.getProperty("changeset.vectors", "../packages/shared/test/changeset-vectors.json");
        vectors = JsonParser.parseString(Files.readString(Path.of(path), StandardCharsets.UTF_8)).getAsJsonObject();
    }

    private static JsonArray cases(String name) {
        JsonArray a = vectors.getAsJsonArray(name);
        assertTrue(a.size() > 0, name + " has cases");
        return a;
    }

    @Test
    void maxOps() {
        assertEquals(vectors.get("maxOps").getAsInt(), Changeset.MAX_OPS, "Changeset.MAX_OPS matches the proposal cap");
    }

    @Test
    void defHash() {
        for (JsonElement c : cases("defHash")) {
            JsonObject o = c.getAsJsonObject();
            assertEquals(o.get("defHash").getAsString(), ProposalNorm.defHash(o.getAsJsonObject("dataType")),
                "defHash of " + o.get("dataType"));
        }
    }

    @Test
    void normStorage() {
        for (JsonElement c : cases("normStorage")) {
            JsonObject o = c.getAsJsonObject();
            assertEquals(o.get("out").getAsString(), ProposalNorm.normStorage(o.get("in").getAsString()), o.get("in").getAsString());
        }
    }

    @Test
    void normType() {
        for (JsonElement c : cases("normType")) {
            JsonObject o = c.getAsJsonObject();
            assertEquals(o.get("out").getAsString(), ProposalNorm.normType(o.get("in").getAsString()), o.get("in").getAsString());
        }
    }

    @Test
    void normSignature() {
        for (JsonElement c : cases("normSignature")) {
            JsonObject o = c.getAsJsonObject();
            assertEquals(o.get("out").getAsString(), ProposalNorm.normSignature(o.get("in").getAsString()), o.get("in").getAsString());
        }
    }

    @Test
    void normConvention() {
        for (JsonElement c : cases("normConvention")) {
            JsonObject o = c.getAsJsonObject();
            assertEquals(o.get("out").getAsString(), ProposalNorm.normConvention(o.get("in").getAsString()), o.get("in").getAsString());
        }
    }

    @Test
    void normAddress() {
        for (JsonElement c : cases("normAddress")) {
            JsonObject o = c.getAsJsonObject();
            assertEquals(o.get("out").getAsString(), ProposalNorm.normAddress(o.get("in").getAsString()), o.get("in").getAsString());
        }
    }

    @Test
    void addrEq() {
        for (JsonElement c : cases("addrEq")) {
            JsonObject o = c.getAsJsonObject();
            assertEquals(o.get("out").getAsBoolean(), ProposalNorm.addrEq(o.get("a").getAsString(), o.get("b").getAsString()),
                o.get("a") + " vs " + o.get("b"));
        }
    }

    @Test
    void stableStringifySortsKeysAndEscapesLikeJavaScript() {
        JsonObject o = new JsonObject();
        o.addProperty("b", 1);
        o.addProperty("a", "q\"\\\n\u0001é");
        o.add("c", new JsonArray());
        assertEquals("{\"a\":\"q\\\"\\\\\\n\\u0001é\",\"b\":1,\"c\":[]}", ProposalNorm.stableStringify(o));
    }
}
