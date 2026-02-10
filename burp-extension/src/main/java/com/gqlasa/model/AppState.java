package com.gqlasa.model;

import java.util.ArrayList;
import java.util.List;

public class AppState {
    private static final AppState INSTANCE = new AppState();
    public static AppState get() { return INSTANCE; }

    public GeneralConfig config = new GeneralConfig();
    public String schemaJson = "";
    public long schemaRevision = 0;
    // When we attempt automatic introspection import and fail, we keep schemaJson empty
    // and surface a user-friendly message in the Schema tab.
    public boolean schemaAutoFetchFailed = false;
    public String schemaAutoFetchMessage = "";
    public String targetType = "";
    public List<PathRow> lastResults = new ArrayList<>();

    private AppState() {}
}
