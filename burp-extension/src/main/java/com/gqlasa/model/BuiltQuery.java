package com.gqlasa.model;

import java.util.LinkedHashMap;
import java.util.Map;

public class BuiltQuery {
    public String operationName;
    public String query; // GraphQL text with \n
    public Map<String, Object> variables = new LinkedHashMap<>();

    public BuiltQuery() {}

    public BuiltQuery(String operationName, String query, Map<String, Object> variables) {
        this.operationName = operationName;
        this.query = query;
        this.variables = variables;
    }
}
