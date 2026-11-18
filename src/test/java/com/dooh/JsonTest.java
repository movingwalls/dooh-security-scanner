package com.dooh;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Map;
import org.junit.jupiter.api.Test;

class JsonTest {
    @Test
    void parsesNestedNucleiStyleObject() {
        Map<String, Object> m = Json.asMap(Json.parse(
                "{\"a\":{\"b\":[1,\"x\\\"y\",true,null]},\"s\":\"\\u00e9\\n\"}"));
        assertEquals(4, Json.asList(Json.asMap(m.get("a")).get("b")).size());
        assertEquals("x\"y", Json.asList(Json.asMap(m.get("a")).get("b")).get(1));
        assertEquals("\u00e9\n", m.get("s"));
    }

    @Test
    void rejectsMalformedInput() {
        assertThrows(RuntimeException.class, () -> Json.parse("{\"a\":"));
        assertThrows(RuntimeException.class, () -> Json.parse("{} x"));
    }

    @Test
    void quoteEscapes() {
        assertEquals("\"a\\\"b\\\\c\\n\"", Json.quote("a\"b\\c\n"));
    }
}
