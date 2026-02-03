package com.gqlasa.core.schema;

import java.util.HashMap;
import java.util.Map;

public class SchemaIndex {
    public Map<String, GqlTypeDef> types = new HashMap<>();
    public String queryTypeName;
    public String mutationTypeName;
}
