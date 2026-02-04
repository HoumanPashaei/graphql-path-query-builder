package com.gqlasa.ui.querybuilder;

import com.gqlasa.model.AppState;
import com.gqlasa.model.GeneralConfig;

import javax.swing.*;
import java.awt.*;

public class QueryBuilderPanel extends JPanel {

    private static QueryBuilderPanel INSTANCE;

    private final JTabbedPane subtabs;
    private final GeneralConfigPanel generalConfigPanel;
    private final SchemaPanel schemaPanel;
    private final PathsToQueriesPanel pathsPanel;

    public QueryBuilderPanel() {
        super(new BorderLayout());
        INSTANCE = this;

        subtabs = new JTabbedPane();
        generalConfigPanel = new GeneralConfigPanel();
        schemaPanel = new SchemaPanel();
        pathsPanel = new PathsToQueriesPanel();

        subtabs.addTab("General Config", generalConfigPanel);
        subtabs.addTab("Schema", schemaPanel);
        subtabs.addTab("Paths → Queries", pathsPanel);

        add(subtabs, BorderLayout.CENTER);
    }

    public static QueryBuilderPanel getInstance() {
        return INSTANCE;
    }

    public void applyImportedIntrospection(GeneralConfig cfg, String schemaJson, boolean switchToPaths) {
        // Update state
        AppState st = AppState.get();
        if (st.config == null) { st.config = new com.gqlasa.model.GeneralConfig(); }
        st.config.applyFrom(cfg);
st.schemaJson = schemaJson == null ? "" : schemaJson;
        st.schemaRevision++;
        st.targetType = "";
        st.lastResults.clear();

        // Refresh UI (on EDT)
        SwingUtilities.invokeLater(() -> {
            generalConfigPanel.loadFromState();
            schemaPanel.loadSchemaFromState();
            pathsPanel.onSchemaChanged();
            if (switchToPaths) {
                subtabs.setSelectedComponent(pathsPanel);
            }
        });
    }

    public void focusPathsTab() {
        SwingUtilities.invokeLater(() -> subtabs.setSelectedComponent(pathsPanel));
    }
}
