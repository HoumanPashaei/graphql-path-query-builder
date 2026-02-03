package com.gqlasa.model;

public class PathRow {
    public int index;
    public String rootField;
    public int depth;
    public boolean hasRequiredArgs;
    public String pathText;
    public BuiltQuery builtQuery;

    public PathRow(int index, String rootField, int depth, boolean hasRequiredArgs, String pathText, BuiltQuery builtQuery) {
        this.index = index;
        this.rootField = rootField;
        this.depth = depth;
        this.hasRequiredArgs = hasRequiredArgs;
        this.pathText = pathText;
        this.builtQuery = builtQuery;
    }
}
