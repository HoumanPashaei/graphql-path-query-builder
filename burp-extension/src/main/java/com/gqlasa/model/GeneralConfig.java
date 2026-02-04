package com.gqlasa.model;

import java.util.ArrayList;
import java.util.List;

public class GeneralConfig {
    public String scheme = "https";
    public String host = "example.com";
    public int port = 443;
    public String endpointPath = "/graphql";
    public String method = "POST";
    public String contentType = "application/json";

    public List<HeaderKV> headers = new ArrayList<>();

    public GeneralConfig() {
        headers.add(new HeaderKV("User-Agent", "GQL-ASA"));
        headers.add(new HeaderKV("Accept", "application/json"));
    }


    public void applyFrom(GeneralConfig other) {
        if (other == null) return;
        this.scheme = other.scheme;
        this.host = other.host;
        this.port = other.port;
        this.endpointPath = other.endpointPath;
        this.method = other.method;
        this.contentType = other.contentType;

        if (this.headers == null) {
            this.headers = new java.util.ArrayList<>();
        }
        this.headers.clear();
        if (other.headers != null) {
            for (HeaderKV h : other.headers) {
                this.headers.add(new HeaderKV(h.key, h.value));
            }
        }
    }

    public GeneralConfig deepCopy() {
        GeneralConfig c = new GeneralConfig();
        c.scheme = this.scheme;
        c.host = this.host;
        c.port = this.port;
        c.endpointPath = this.endpointPath;
        c.method = this.method;
        c.contentType = this.contentType;        c.headers = new java.util.ArrayList<>();
        if (this.headers != null) {
            for (HeaderKV h : this.headers) {
                c.headers.add(new HeaderKV(h.key, h.value));
            }
        }
        return c;
    }

}
