package com.gqlasa.core.schema;

public class GqlInputValue {
    public String name;
    public GqlTypeRef type;

    public boolean isRequired() {
        return type != null && "NON_NULL".equals(type.kind);
    }
}
