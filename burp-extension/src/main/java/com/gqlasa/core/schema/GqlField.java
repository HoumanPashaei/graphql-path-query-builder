package com.gqlasa.core.schema;

import java.util.ArrayList;
import java.util.List;

public class GqlField {
    public String name;
    public GqlTypeRef type;
    public List<GqlInputValue> args = new ArrayList<>();

    public boolean hasRequiredArgs() {
        if (args == null) return false;
        for (GqlInputValue a : args) {
            if (a != null && a.isRequired()) return true;
        }
        return false;
    }
}
