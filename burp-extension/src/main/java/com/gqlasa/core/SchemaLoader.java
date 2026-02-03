package com.gqlasa.core;

import com.fasterxml.jackson.databind.JsonNode;
import com.gqlasa.core.schema.*;
import com.gqlasa.util.Strings;

import static com.gqlasa.util.Json.MAPPER;

public final class SchemaLoader {
    private SchemaLoader(){}

    public static SchemaIndex loadFromIntrospectionJson(String schemaJson) throws Exception {
        JsonNode root = MAPPER.readTree(schemaJson);
        JsonNode schemaNode = root.path("data").path("__schema");
        if (schemaNode.isMissingNode()) schemaNode = root.path("__schema");
        if (schemaNode.isMissingNode()) {
            throw new IllegalArgumentException("Invalid schema JSON: could not find data.__schema or __schema.");
        }

        SchemaIndex idx = new SchemaIndex();
        idx.queryTypeName = schemaNode.path("queryType").path("name").asText(null);
        idx.mutationTypeName = schemaNode.path("mutationType").path("name").asText(null);

        JsonNode types = schemaNode.path("types");
        if (!types.isArray()) {
            throw new IllegalArgumentException("Invalid schema JSON: __schema.types is not an array.");
        }

        for (JsonNode t : types) {
            String name = t.path("name").asText(null);
            String kind = t.path("kind").asText(null);
            if (Strings.isBlank(name) || Strings.isBlank(kind)) continue;

            GqlTypeDef def = new GqlTypeDef();
            def.name = name;
            def.kind = kind;

            JsonNode fields = t.path("fields");
            if (fields.isArray()) {
                for (JsonNode f : fields) {
                    GqlField gf = new GqlField();
                    gf.name = f.path("name").asText();
                    gf.type = parseTypeRef(f.path("type"));
                    JsonNode args = f.path("args");
                    if (args.isArray()) {
                        for (JsonNode a : args) {
                            GqlInputValue iv = new GqlInputValue();
                            iv.name = a.path("name").asText();
                            iv.type = parseTypeRef(a.path("type"));
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

    private static GqlTypeRef parseTypeRef(JsonNode node) {
        if (node == null || node.isMissingNode() || node.isNull()) return null;
        GqlTypeRef tr = new GqlTypeRef();
        tr.kind = node.path("kind").asText(null);
        tr.name = node.path("name").isNull() ? null : node.path("name").asText(null);
        JsonNode ofType = node.path("ofType");
        if (ofType != null && !ofType.isMissingNode() && !ofType.isNull()) {
            tr.ofType = parseTypeRef(ofType);
        }
        return tr;
    }
}
