package com.gqlasa.ui;

import com.gqlasa.ui.querybuilder.QueryBuilderPanel;

import javax.swing.*;
import java.awt.*;

public class MainPanel extends JPanel {
    public MainPanel() {
        super(new BorderLayout());
        JTabbedPane tabs = new JTabbedPane();

        tabs.addTab("Query Builder", new QueryBuilderPanel());
        tabs.addTab("Voyager", placeholder("Planned"));
        tabs.addTab("CSRF Scanner", placeholder("Planned"));
        tabs.addTab("DoS (GraphQL Cop)", placeholder("Planned"));
        tabs.addTab("CSWS Hijacking", placeholder("Planned"));

        add(tabs, BorderLayout.CENTER);
        setBorder(BorderFactory.createEmptyBorder(8,8,8,8));
    }

    private JPanel placeholder(String text) {
        JPanel p = new JPanel(new BorderLayout());
        p.add(new JLabel(text), BorderLayout.CENTER);
        return p;
    }
}
