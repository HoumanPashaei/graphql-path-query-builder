package com.gqlasa.core;

import com.gqlasa.core.schema.*;
import com.gqlasa.util.Json;
import com.gqlasa.util.Strings;

import java.util.List;
import java.util.Map;

/**
 * Loads a GraphQL introspection schema JSON into an in-memory index.
 *
 * Implemented without external JSON libraries for Burp classloader safety.
 */
public final class SchemaLoader {
    private SchemaLoader(){}

    @SuppressWarnings("unchecked")
    public static SchemaIndex loadFromIntrospectionJson(String schemaJson) throws Exception {
        Object parsed = Json.parse(schemaJson);
        if (!(parsed instanceof Map)) {
            throw new IllegalArgumentException("Invalid schema JSON: not an object");
        }
        Map<String, Object> root = (Map<String, Object>) parsed;

        // Accept either { data: { __schema: ... } } or { __schema: ... }
        Object schemaObj = null;
        Object dataObj = root.get("data");
        if (dataObj instanceof Map) {
            schemaObj = ((Map<String, Object>) dataObj).get("__schema");
        }
        if (schemaObj == null) schemaObj = root.get("__schema");
        if (!(schemaObj instanceof Map)) {
            throw new IllegalArgumentException("Invalid schema JSON: could not find data.__schema or __schema.");
        }

        Map<String, Object> schema = (Map<String, Object>) schemaObj;

        SchemaIndex idx = new SchemaIndex();
        idx.queryTypeName = readName(schema.get("queryType"));
        idx.mutationTypeName = readName(schema.get("mutationType"));

        Object typesObj = schema.get("types");
        if (!(typesObj instanceof List)) {
            throw new IllegalArgumentException("Invalid schema JSON: __schema.types is not an array.");
        }

        for (Object tObj : (List<?>) typesObj) {
            if (!(tObj instanceof Map)) continue;
            Map<String, Object> t = (Map<String, Object>) tObj;
            String name = asString(t.get("name"));
            String kind = asString(t.get("kind"));
            if (Strings.isBlank(name) || Strings.isBlank(kind)) continue;

            GqlTypeDef def = new GqlTypeDef();
            def.name = name;
            def.kind = kind;

            Object fieldsObj = t.get("fields");
            if (fieldsObj instanceof List) {
                for (Object fObj : (List<?>) fieldsObj) {
                    if (!(fObj instanceof Map)) continue;
                    Map<String, Object> f = (Map<String, Object>) fObj;

                    GqlField gf = new GqlField();
                    gf.name = asString(f.get("name"));
                    gf.type = parseTypeRef(f.get("type"));

                    Object argsObj = f.get("args");
                    if (argsObj instanceof List) {
                        for (Object aObj : (List<?>) argsObj) {
                            if (!(aObj instanceof Map)) continue;
                            Map<String, Object> a = (Map<String, Object>) aObj;
                            GqlInputValue iv = new GqlInputValue();
                            iv.name = asString(a.get("name"));
                            iv.type = parseTypeRef(a.get("type"));
                            gf.args.add(iv);
                        }
                    }

                    def.fields.add(gf);
                }
            }

            idx.types.put(name, def);
        }

        return idx;
    }

    private static String readName(Object o) {
        if (o instanceof Map) return asString(((Map<?, ?>) o).get("name"));
        return null;
    }

    @SuppressWarnings("unchecked")
    private static GqlTypeRef parseTypeRef(Object node) {
        if (!(node instanceof Map)) return null;
        Map<String, Object> m = (Map<String, Object>) node;
        GqlTypeRef tr = new GqlTypeRef();
        tr.kind = asString(m.get("kind"));
        tr.name = asString(m.get("name"));
        Object ofType = m.get("ofType");
        if (ofType instanceof Map) {
            tr.ofType = parseTypeRef(ofType);
        }
        return tr;
    }

    private static String asString(Object o) {
        return (o == null) ? null : String.valueOf(o);
    }
}
