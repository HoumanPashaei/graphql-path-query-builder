package com.gqlasa.ui.querybuilder;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import com.gqlasa.model.GeneralConfig;
import com.gqlasa.model.HeaderKV;
import com.gqlasa.ui.MainPanel;
import com.gqlasa.ui.querybuilder.QueryBuilderPanel;

import javax.swing.*;
import java.awt.*;
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
        // Prefer editor context (Repeater/Intruder/etc), fallback to selection (Proxy/HTTP history)
        var rrOpt = event.messageEditorRequestResponse();
        var selected = event.selectedRequestResponses();

        burp.api.montoya.http.message.HttpRequestResponse rr = null;
        if (rrOpt.isPresent()) {
            rr = rrOpt.get().requestResponse();
        } else if (selected != null && !selected.isEmpty()) {
            rr = selected.get(0);
        }

        if (rr == null) {
            return java.util.List.of();
        }

        final var rrFinal = rr;

        JMenuItem item = new JMenuItem("Send to QueryBuilder");
        item.addActionListener(e -> {
            HttpRequest req = rrFinal.request();
            HttpResponse resp = rrFinal.response();

            // If no response is available, try sending the request
            if (resp == null) {
                try {
                    var sent = api.http().sendRequest(req);
                    resp = sent.response();
                } catch (Exception ignored) { }
            }

            String schemaJson = resp != null ? resp.bodyToString() : "";

            GeneralConfig cfg = new GeneralConfig();
            try {
                URI uri = URI.create(req.url());
                cfg.scheme = uri.getScheme() == null ? "https" : uri.getScheme();
                cfg.host = uri.getHost() == null ? "" : uri.getHost();
                int p = uri.getPort();
                cfg.port = (p == -1)
                        ? ("https".equalsIgnoreCase(cfg.scheme) ? 443 : 80)
                        : p;
                cfg.endpointPath = uri.getPath() == null ? "/" : uri.getPath();
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

            // copy relevant headers
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
        });

        JMenu menu = new JMenu("GQL-ASA");
        menu.add(item);
        return java.util.List.of((Component) menu);
    }
}
