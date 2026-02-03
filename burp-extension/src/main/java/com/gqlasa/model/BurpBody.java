package com.gqlasa.model;

import java.util.LinkedHashMap;
import java.util.Map;

public class BurpBody {
    public String query;
    public String operationName;
    public Map<String, Object> variables = new LinkedHashMap<>();

    public BurpBody() {}

    public BurpBody(String query, String operationName, Map<String, Object> variables) {
        this.query = query;
        this.operationName = operationName;
        this.variables = variables;
    }
}
