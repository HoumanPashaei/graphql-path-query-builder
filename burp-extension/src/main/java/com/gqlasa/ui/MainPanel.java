package com.gqlasa.ui;

import com.gqlasa.ui.querybuilder.QueryBuilderPanel;

import javax.swing.*;
import java.awt.*;

public class MainPanel extends JPanel {

    private static MainPanel INSTANCE;

    private final JTabbedPane tabs;
    private final QueryBuilderPanel queryBuilderPanel;

    public MainPanel() {
        super(new BorderLayout());
        INSTANCE = this;

        tabs = new JTabbedPane();
        queryBuilderPanel = new QueryBuilderPanel();

        tabs.addTab("Query Builder", queryBuilderPanel);
        tabs.addTab("Voyager", placeholder("Planned"));
        tabs.addTab("CSRF Scanner", placeholder("Planned"));
        tabs.addTab("DoS (GraphQL Cop)", placeholder("Planned"));
        tabs.addTab("CSWS Hijacking", placeholder("Planned"));

        add(tabs, BorderLayout.CENTER);
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
    }

    public static MainPanel getInstance() {
        return INSTANCE;
    }

    public void selectQueryBuilder() {
        SwingUtilities.invokeLater(() -> tabs.setSelectedIndex(0));
    }

    public QueryBuilderPanel queryBuilder() {
        return queryBuilderPanel;
    }

    private JPanel placeholder(String text) {
        JPanel p = new JPanel(new BorderLayout());
        p.add(new JLabel(text, SwingConstants.CENTER), BorderLayout.CENTER);
        return p;
    }
}
