package com.gqlasa.core.schema;

public class GqlTypeRef {
    public String kind;
    public String name;
    public GqlTypeRef ofType;

    public String unwrapName() {
        GqlTypeRef t = this;
        while (t != null && ("NON_NULL".equals(t.kind) || "LIST".equals(t.kind))) {
            t = t.ofType;
        }
        return t == null ? null : t.name;
    }

    public String unwrapKind() {
        GqlTypeRef t = this;
        while (t != null && ("NON_NULL".equals(t.kind) || "LIST".equals(t.kind))) {
            t = t.ofType;
        }
        return t == null ? null : t.kind;
    }

    public String renderTypeSDL() {
        if ("NON_NULL".equals(kind) && ofType != null) return ofType.renderTypeSDL() + "!";
        if ("LIST".equals(kind) && ofType != null) return "[" + ofType.renderTypeSDL() + "]";
        return name != null ? name : "Unknown";
    }
}
