package com.gqlasa.ui.querybuilder;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import com.gqlasa.model.GeneralConfig;
import com.gqlasa.model.HeaderKV;
import com.gqlasa.ui.MainPanel;

import javax.swing.*;
import java.awt.*;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class IntrospectionImportProvider implements ContextMenuItemsProvider {

    // Introspection query used across the extension (matches DoS Scanner's fetch logic).
    // Kept as a single line to avoid any JSON escaping/transport edge cases.
    private static final String INTROSPECTION_QUERY =
            "query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } } " +
            "fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } " +
            "fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } " +
            "fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } }";

    private final MontoyaApi api;

    public IntrospectionImportProvider(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        HttpRequestResponse rr = pickOneRequestResponse(event);
        if (rr == null) return List.of();

        final HttpRequestResponse rrFinal = rr;

        JMenuItem sendToQB = new JMenuItem("Send to QueryBuilder");
        sendToQB.addActionListener(e -> sendToQueryBuilder(rrFinal));

        JMenuItem sendToCsrf = new JMenuItem("Send to CSRF Scanner");
        sendToCsrf.addActionListener(e -> sendToCsrfScanner(rrFinal));

        JMenuItem sendToDos = new JMenuItem("Send to DoS Scanner");
        sendToDos.addActionListener(e -> sendToDosScanner(rrFinal));

        JMenu root = new JMenu("GQL-ASA");
        root.add(sendToQB);
        root.add(sendToCsrf);
        root.add(sendToDos);

        return List.of((Component) root);
    }

    private HttpRequestResponse pickOneRequestResponse(ContextMenuEvent event) {
        // Prefer editor context (Repeater/Intruder/etc), fallback to selection (Proxy/HTTP history)
        var rrOpt = event.messageEditorRequestResponse();
        var selected = event.selectedRequestResponses();

        if (rrOpt.isPresent()) {
            return rrOpt.get().requestResponse();
        }
        if (selected != null && !selected.isEmpty()) {
            return selected.get(0);
        }
        return null;
    }

    private void sendToQueryBuilder(HttpRequestResponse rr) {
        HttpRequest req = rr.request();
        HttpResponse resp = rr.response();

        // If no response is available, try sending the request
        if (resp == null) {
            try {
                var sent = api.http().sendRequest(req);
                resp = sent.response();
            } catch (Exception ignored) {
            }
        }

        String bodyText = safeBodyToString(req);
        boolean looksLikeIntrospectionRequest = bodyText.contains("__schema") || bodyText.contains("IntrospectionQuery");

        // Do NOT blindly put the response body into the Schema tab.
        // Only accept actual introspection responses (contain __schema).
        String responseBody = (resp != null) ? resp.bodyToString() : "";
        boolean looksLikeSchemaResponse = responseBody != null && (responseBody.contains("\"__schema\"") || responseBody.contains("__schema"));

        String schemaJson = "";
        boolean schemaLoaded = false;

        // Build target config from the request's HttpService/path.
        // (Avoid reflection here; Montoya exposes host()/port()/secure() directly and
        // reflection mistakes can silently break auto-introspection.)
        GeneralConfig cfg = new GeneralConfig();
        try {
            var svc = req.httpService();
            // Prefer the raw Host header (may include port), because some apps
            // and reverse proxies route based on the Host header value.
            String hostHeader = null;
            try { hostHeader = req.headerValue("Host"); } catch (Exception ignored) {}
            cfg.host = (hostHeader != null && !hostHeader.isBlank())
                    ? hostHeader.trim()
                    : ((svc == null) ? "" : svc.host());
            cfg.port = (svc == null) ? 443 : svc.port();
            cfg.scheme = (svc != null && svc.secure()) ? "https" : "http";

            String path = null;
            try { path = req.path(); } catch (Exception ignored) {}
            if (path == null || path.isBlank()) {
                // Fallback: parse request line
                String raw = req.toString();
                int eol = raw.indexOf("\r\n");
                String first = eol > 0 ? raw.substring(0, eol) : raw;
                String[] parts = first.split(" ");
                if (parts.length >= 2) path = parts[1];
            }
            cfg.endpointPath = (path == null || path.isBlank()) ? "/graphql" : path;
        } catch (Exception ex) {
            cfg.scheme = "https";
            cfg.host = "";
            cfg.port = 443;
            cfg.endpointPath = "/graphql";
        }

        cfg.method = "POST";

        // content-type from request headers (default json)
        String ct = req.headerValue("Content-Type");
        cfg.contentType = (ct == null || ct.isBlank()) ? "application/json" : ct;

        // copy headers
        List<HeaderKV> hdrs = new ArrayList<>();
        for (var h : req.headers()) {
            String name = h.name();
            if (name == null) continue;
            String n = name.toLowerCase();

            if (n.equals("host") || n.equals("content-length")) continue;
            if (n.equals("connection")) continue;

            hdrs.add(new HeaderKV(name, h.value()));
        }
        cfg.headers = hdrs;

        if (looksLikeSchemaResponse) {
            // User already provided an introspection response (e.g., from Repeater).
            schemaJson = responseBody;
            schemaLoaded = true;
        } else if (looksLikeIntrospectionRequest) {
            // User provided an introspection request but without a response.
            // Fetch it ourselves using a fresh request with correct framing.
            try {
                String fetched = tryFetchIntrospection(req, cfg);
                if (fetched != null && (fetched.contains("\"__schema\"") || fetched.contains("__schema"))) {
                    schemaJson = fetched;
                    schemaLoaded = true;
                }
            } catch (Exception ignored) {}
        }

        // We intentionally do NOT auto-introspect for normal GraphQL queries.
        // If the user wants schema loaded automatically, they can send an
        // introspection request/response from Repeater, or import schema JSON.
        com.gqlasa.model.AppState.get().schemaAutoFetchFailed = !schemaLoaded;
        com.gqlasa.model.AppState.get().schemaAutoFetchMessage = schemaLoaded
                ? ""
                : "Schema: not loaded (please import schema JSON or send an introspection response)";

        // Apply into UI and switch to Paths→Queries
        MainPanel mp = MainPanel.getInstance();
        if (mp != null) {
            mp.selectQueryBuilder();
            QueryBuilderPanel qb = QueryBuilderPanel.getInstance();
            if (qb != null) {
                qb.applyImportedIntrospection(cfg, schemaJson, true);
            }
        }
    }

    private String safeBodyToString(HttpRequest req) {
        try {
            String s = req.bodyToString();
            return s == null ? "" : s;
        } catch (Exception e) {
            return "";
        }
    }

    private String tryFetchIntrospection(HttpRequest baseReq, GeneralConfig cfg) {
        if (baseReq == null) return null;

        // IMPORTANT:
        // We previously tried to reuse the original request and only swap the body.
        // In practice, some Montoya/Burp combinations keep stale framing/length or
        // normalize headers differently, which can cause the server to reject the body
        // or the request to never reach the intended endpoint.
        //
        // To behave like Repeater (where introspection works for the user), we build
        // a fresh raw HTTP request string with correct Content-Length using the same
        // target HttpService, then send it via Montoya.
        try {
            cfg.contentType = "application/json";
        } catch (Exception ignored) {}

        com.gqlasa.model.BuiltQuery iq = new com.gqlasa.model.BuiltQuery();
        iq.query = INTROSPECTION_QUERY;
        iq.operationName = "IntrospectionQuery";
        iq.variables = new LinkedHashMap<>();

        String raw = com.gqlasa.core.BurpRequestBuilder.buildHttpRequest(cfg, iq);
        HttpRequest iReq = HttpRequest.httpRequest(baseReq.httpService(), raw);

        var rr = api.http().sendRequest(iReq);
        if (rr == null || rr.response() == null) return null;
        String body = rr.response().bodyToString();
        // Helpful diagnostics for cases where users can fetch schema in Repeater
        // but auto-fetch fails (e.g., WAF rules, auth issues, blocked headers).
        if (body == null || body.isBlank() || !(body.contains("__schema") || body.contains("\"__schema\""))) {
            try {
                int sc = rr.response().statusCode();
                api.logging().logToOutput("[QueryBuilder] Auto-introspection did not return schema. HTTP=" + sc);
                String snippet = body == null ? "" : body;
                if (snippet.length() > 300) snippet = snippet.substring(0, 300);
                if (!snippet.isBlank()) api.logging().logToOutput("[QueryBuilder] Introspection response snippet: " + snippet);
                com.gqlasa.model.AppState.get().schemaAutoFetchMessage = "Schema: not loaded (introspection failed — HTTP=" + sc + ")";
            } catch (Exception ignored) {}
        }
        return body;
    }

    // kept for backward compatibility if used elsewhere in future; currently unused
    @SuppressWarnings("unused")
    private boolean needsPort(GeneralConfig cfg) {
        if (cfg == null) return true;
        if ("https".equalsIgnoreCase(cfg.scheme)) return cfg.port != 443;
        if ("http".equalsIgnoreCase(cfg.scheme)) return cfg.port != 80;
        return true;
    }

    
    /**
     * DoS (GraphQL Cop) hook.
     * مشابه CSRF، با Reflection تا در صورت نبودن کلاس/تب، افزونه نشکند.
     */
    private void sendToDosScanner(HttpRequestResponse rr) {
        try {
            MainPanel mp = MainPanel.getInstance();
            if (mp != null) {
                // تلاش برای انتخاب تب DoS در صورت وجود
                tryInvoke(mp, "selectDosScanner");
            }

            Class<?> panelClazz = Class.forName("com.gqlasa.ui.dos.DosScannerPanel");
            Method getInstance = panelClazz.getMethod("getInstance");
            Object panel = getInstance.invoke(null);

            if (panel != null) {
                tryInvoke(panel, "importFromHttpRequestResponse", HttpRequestResponse.class, rr);
            }
        } catch (Exception ignored) {
        }
    }

/**
     * CSRF Scanner hook.
     * برای اینکه QueryBuilder هیچ‌وقت با تغییرات CSRF نشکند، این قسمت را با Reflection زده‌ایم:
     * اگر تب/کلاس CSRF وجود داشته باشد، اجرا می‌شود؛ اگر وجود نداشت، هیچ اتفاقی نمی‌افتد.
     */
    private void sendToCsrfScanner(HttpRequestResponse rr) {
        try {
            MainPanel mp = MainPanel.getInstance();
            if (mp != null) {
                // mp.selectCsrfScanner() اگر وجود داشت
                tryInvoke(mp, "selectCsrfScanner");
            }

            Class<?> panelClazz = Class.forName("com.gqlasa.ui.csrf.CsrfScannerPanel");
            Method getInstance = panelClazz.getMethod("getInstance");
            Object panel = getInstance.invoke(null);

            if (panel != null) {
                // panel.importFromHttpRequestResponse(HttpRequestResponse) اگر وجود داشت
                tryInvoke(panel, "importFromHttpRequestResponse", HttpRequestResponse.class, rr);
            }
        } catch (Exception ignored) {
        }
    }

    private void tryInvoke(Object target, String methodName, Class<?>... paramTypes) {
        try {
            Method m = target.getClass().getMethod(methodName, paramTypes);
            m.invoke(target, new Object[paramTypes.length]);
        } catch (Exception ignored) {
        }
    }

    private void tryInvoke(Object target, String methodName, Class<?> paramType, Object arg) {
        try {
            Method m = target.getClass().getMethod(methodName, paramType);
            m.invoke(target, arg);
        } catch (Exception ignored) {
        }
    }
}
