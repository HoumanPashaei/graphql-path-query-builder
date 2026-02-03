package com.gqlasa.ui.querybuilder;

import javax.swing.*;
import java.awt.*;

public class QueryBuilderPanel extends JPanel {
    public QueryBuilderPanel() {
        super(new BorderLayout());
        JTabbedPane subtabs = new JTabbedPane();
        subtabs.addTab("General Config", new GeneralConfigPanel());
        subtabs.addTab("Schema", new SchemaPanel());
        subtabs.addTab("Paths → Queries", new PathsToQueriesPanel());

        add(subtabs, BorderLayout.CENTER);
    }
}
