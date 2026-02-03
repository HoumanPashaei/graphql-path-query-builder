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
}
