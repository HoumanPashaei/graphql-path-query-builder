package com.gqlasa.util;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Map;
import com.fasterxml.jackson.databind.SerializationFeature;

public final class Json {
    private Json(){}

    public static final ObjectMapper MAPPER = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT);

    public static String toCompactString(Object obj) {
        try {
            return new ObjectMapper().writeValueAsString(obj);
        } catch (Exception e) {
            throw new RuntimeException("Failed to serialize JSON", e);
        }
    }

    public static String toPrettyString(Object obj) {
        try {
            return MAPPER.writeValueAsString(obj);
        } catch (Exception e) {
            throw new RuntimeException("Failed to serialize JSON", e);
        }
    }

    public static Map<String, Object> parseMap(String json) {
        try {
            if (json == null) return Map.of();
            return MAPPER.readValue(json, new TypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String pretty(Map<String, Object> map) {
        try {
            return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(map);
        } catch (Exception e) {
            return String.valueOf(map);
        }
    }

    public static String compact(Object obj) {
        try {
            return MAPPER.writeValueAsString(obj);
        } catch (Exception e) {
            return String.valueOf(obj);
        }
    }

    /**
     * Backwards-compatible alias used by some panels.
     */
    public static String stringify(Map<String, Object> map) {
        return compact(map);
    }

    /**
     * Backwards-compatible alias used by some panels.
     */
    public static String stringify(List<Map<String, Object>> list) {
        return compact(list);
    }

    /**
     * Parse arbitrary JSON into Map/List/scalars.
     */
    public static Object parse(String json) {
        try {
            if (json == null) return null;
            return MAPPER.readValue(json, new TypeReference<Object>() {});
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
