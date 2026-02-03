package com.gqlasa.core;

import com.gqlasa.model.BuiltQuery;
import com.gqlasa.model.BurpBody;
import com.gqlasa.model.GeneralConfig;
import com.gqlasa.model.HeaderKV;
import com.gqlasa.util.Json;
import com.gqlasa.util.Strings;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public final class BurpRequestBuilder {
    private BurpRequestBuilder(){}

    public static String buildJsonBody(BuiltQuery q) {
        BurpBody body = new BurpBody(q.query, q.operationName, q.variables);
        return Json.toCompactString(body);
    }

    public static String buildHttpRequest(GeneralConfig cfg, BuiltQuery q) {
        String method = Strings.isBlank(cfg.method) ? "POST" : cfg.method.trim().toUpperCase();
        String path = Strings.isBlank(cfg.endpointPath) ? "/graphql" : cfg.endpointPath.trim();
        if (!path.startsWith("/")) path = "/" + path;

        String body = buildJsonBody(q);
        int len = body.getBytes(StandardCharsets.UTF_8).length;

        List<String> lines = new ArrayList<>();
        lines.add(method + " " + path + " HTTP/1.1");
        lines.add("Host: " + cfg.host);
        lines.add("Content-Type: " + (Strings.isBlank(cfg.contentType) ? "application/json" : cfg.contentType));
        lines.add("Content-Length: " + len);

        if (cfg.headers != null) {
            for (HeaderKV kv : cfg.headers) {
                if (kv == null || Strings.isBlank(kv.key)) continue;
                String kLower = kv.key.trim().toLowerCase();
                if (kLower.equals("host") || kLower.equals("content-length") || kLower.equals("content-type")) continue;
                lines.add(kv.key.trim() + ": " + Strings.nullToEmpty(kv.value));
            }
        }

        lines.add("");
        lines.add(body);

        return String.join("\r\n", lines);
    }
}
