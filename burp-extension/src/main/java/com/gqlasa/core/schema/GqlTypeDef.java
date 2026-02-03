package com.gqlasa.core.schema;

import java.util.ArrayList;
import java.util.List;

public class GqlTypeDef {
    public String kind;
    public String name;
    public List<GqlField> fields = new ArrayList<>();
    public List<GqlInputValue> inputFields = new ArrayList<>();
    public List<String> enumValues = new ArrayList<>();
}
