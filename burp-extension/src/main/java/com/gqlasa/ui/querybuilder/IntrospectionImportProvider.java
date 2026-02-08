package com.gqlasa.ui.querybuilder;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import com.gqlasa.model.GeneralConfig;
import com.gqlasa.model.HeaderKV;
import com.gqlasa.ui.MainPanel;

import javax.swing.*;
import java.awt.*;
import java.lang.reflect.Method;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

public class IntrospectionImportProvider implements ContextMenuItemsProvider {

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

        String schemaJson = (resp != null) ? resp.bodyToString() : "";

        GeneralConfig cfg = new GeneralConfig();
        try {
            URI uri = URI.create(req.url());
            cfg.scheme = (uri.getScheme() == null) ? "https" : uri.getScheme();
            cfg.host = (uri.getHost() == null) ? "" : uri.getHost();

            int p = uri.getPort();
            cfg.port = (p == -1)
                    ? ("https".equalsIgnoreCase(cfg.scheme) ? 443 : 80)
                    : p;

            cfg.endpointPath = (uri.getPath() == null || uri.getPath().isBlank()) ? "/" : uri.getPath();
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
