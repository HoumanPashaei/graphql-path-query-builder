package com.gqlsurfmapper.gqlasa;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import java.awt.*;

public class GqlAsaExtension implements BurpExtension
{
    @Override
    public void initialize(MontoyaApi api)
    {
        api.extension().setName("GraphQL Surface Mapper");

        JPanel root = new JPanel(new BorderLayout());

        // Top-level tabs: each tool is a main tab
        JTabbedPane toolsTabs = new JTabbedPane();

        toolsTabs.addTab("Query Builder", buildQueryBuilderTab(api));
        toolsTabs.addTab("Voyager", placeholder("Coming soon"));
        toolsTabs.addTab("CSRF Scanner", placeholder("Coming soon"));
        toolsTabs.addTab("DoS Scanner", placeholder("Coming soon"));
        toolsTabs.addTab("CSWS", placeholder("Coming soon"));

        root.add(toolsTabs, BorderLayout.CENTER);

        api.userInterface().registerSuiteTab("GraphQL Surface Mapper", root);
    }

    private JComponent buildQueryBuilderTab(MontoyaApi api)
    {
        JPanel queryBuilderRoot = new JPanel(new BorderLayout());

        // Sub-tabs inside Query Builder
        JTabbedPane qbTabs = new JTabbedPane();
        qbTabs.addTab("General Config", new GeneralConfigPanel(api));
        qbTabs.addTab("Schema", new SchemaPanel(api));
        qbTabs.addTab("Paths → Queries", new PathQueryBuilderPanel(api));

        queryBuilderRoot.add(qbTabs, BorderLayout.CENTER);
        return queryBuilderRoot;
    }

    private JPanel placeholder(String text)
    {
        JPanel p = new JPanel(new BorderLayout());
        JLabel label = new JLabel(text, SwingConstants.CENTER);
        p.add(label, BorderLayout.CENTER);
        return p;
    }
}
