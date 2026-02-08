package com.gqlasa.ui;

import com.gqlasa.ui.querybuilder.QueryBuilderPanel;
import com.gqlasa.ui.csrf.CsrfScannerPanel;
import com.gqlasa.ui.dos.DosScannerPanel;

import javax.swing.*;
import java.awt.*;

public class MainPanel extends JPanel {

    private static MainPanel INSTANCE;

    private final JTabbedPane tabs;
    private final QueryBuilderPanel queryBuilderPanel;
    private final CsrfScannerPanel csrfScannerPanel;
    private final DosScannerPanel dosScannerPanel;

    public MainPanel() {
        super(new BorderLayout());
        INSTANCE = this;

        tabs = new JTabbedPane();
        queryBuilderPanel = new QueryBuilderPanel();
        csrfScannerPanel = new CsrfScannerPanel();
        dosScannerPanel = new DosScannerPanel();

        tabs.addTab("Query Builder", queryBuilderPanel);
        tabs.addTab("CSRF Scanner", csrfScannerPanel);
        tabs.addTab("DoS Scanner", dosScannerPanel);
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


    public void selectCsrfScanner() {
        SwingUtilities.invokeLater(() -> tabs.setSelectedIndex(1));
    }

    public CsrfScannerPanel csrfScanner() {
        return csrfScannerPanel;
    }


    public void selectDosScanner() {
        SwingUtilities.invokeLater(() -> tabs.setSelectedIndex(2));
    }

    public DosScannerPanel dosScanner() {
        return dosScannerPanel;
    }


    private JPanel placeholder(String text) {
        JPanel p = new JPanel(new BorderLayout());
        p.add(new JLabel(text, SwingConstants.CENTER), BorderLayout.CENTER);
        return p;
    }
}
