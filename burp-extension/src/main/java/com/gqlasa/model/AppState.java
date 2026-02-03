package com.gqlasa.model;

import java.util.ArrayList;
import java.util.List;

public class AppState {
    private static final AppState INSTANCE = new AppState();
    public static AppState get() { return INSTANCE; }

    public GeneralConfig config = new GeneralConfig();
    public String schemaJson = "";
    public long schemaRevision = 0;
    public String targetType = "";
    public List<PathRow> lastResults = new ArrayList<>();

    private AppState() {}
}
