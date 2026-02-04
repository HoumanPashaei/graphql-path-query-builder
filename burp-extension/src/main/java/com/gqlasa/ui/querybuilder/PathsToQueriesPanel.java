package com.gqlasa.ui.querybuilder;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.gqlasa.GqlAsaExtension;
import com.gqlasa.core.*;
import com.gqlasa.core.PathFinder.Segment;
import com.gqlasa.core.schema.GqlTypeDef;
import com.gqlasa.core.schema.SchemaIndex;
import com.gqlasa.model.*;
import com.gqlasa.util.Json;
import com.gqlasa.util.Strings;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class PathsToQueriesPanel extends JPanel {

    private final JComboBox<String> targetType = new JComboBox<>();

    private final JSpinner maxDepth = new JSpinner(new SpinnerNumberModel(12, 2, 50, 1));
    private final JSpinner selectionDepth = new JSpinner(new SpinnerNumberModel(8, 1, 25, 1));

    private final JCheckBox includeRequiredArgs = new JCheckBox("Include required args (variables)", true);

    private final JTextField filter = new JTextField("", 28);

    private final PathsTableModel tableModel = new PathsTableModel();
    private final JTable table = new JTable(tableModel);

    private final JLabel pageInfo = new JLabel("Page 1/1");
    private final JLabel status = new JLabel(" ");

    private final Timer statusClear = new Timer(3000, e -> status.setText(" "));

    private final JTextArea preview = new JTextArea();
    private final JTextArea previewPath = new JTextArea();

    private long lastTargetsRev = -1;

    private final Timer schemaWatcher;

    public PathsToQueriesPanel() {
        super(new BorderLayout(10,10));

        statusClear.setRepeats(false);
        status.setForeground(new Color(0, 110, 0));
        status.setFont(status.getFont().deriveFont(Font.BOLD, 16f));
        status.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));

        targetType.setEditable(true);
        targetType.setPrototypeDisplayValue("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
        targetType.setPreferredSize(new Dimension(260, targetType.getPreferredSize().height));
        applyLeftArrow(targetType);

        if (!Strings.isBlank(AppState.get().targetType)) {
            targetType.setSelectedItem(AppState.get().targetType);
        }

        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 6));
        JButton run = new JButton("Build paths & queries");
        JButton onlyPaths = new JButton("Show only paths");
        JButton clear = new JButton("Clear results");

        controls.add(new JLabel("Target:"));
        controls.add(targetType);
        controls.add(new JLabel("Max path depth:"));
        controls.add(maxDepth);
        controls.add(new JLabel("Selection depth:"));
        controls.add(selectionDepth);
        controls.add(includeRequiredArgs);
        controls.add(run);
        controls.add(onlyPaths);
        controls.add(clear);

        run.addActionListener(e -> onRun(false));
        onlyPaths.addActionListener(e -> onRun(true));
        clear.addActionListener(e -> clearResults());

        table.setFillsViewportHeight(true);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        installPathTooltipRenderer();

        // Enable sorting (Index, Depth, etc.)
        table.setAutoCreateRowSorter(true);
        try {
            var sorter = (javax.swing.table.TableRowSorter<?>) table.getRowSorter();
            // Index column (0) numeric
            sorter.setComparator(0, (a, b) -> Integer.compare(Integer.parseInt(a.toString()), Integer.parseInt(b.toString())));
            // Depth column (3) numeric
            sorter.setComparator(3, (a, b) -> Integer.compare(Integer.parseInt(a.toString()), Integer.parseInt(b.toString())));
        } catch (Exception ignored) { }

        JPopupMenu popup = new JPopupMenu();
        JMenuItem copyBody = new JMenuItem("Copy only body (JSON)");
        JMenuItem sendRepeater = new JMenuItem("Send to Repeater");
        popup.add(copyBody);
        popup.add(sendRepeater);

        copyBody.addActionListener(e -> copySelectedBody());
        sendRepeater.addActionListener(e -> sendSelectedToRepeater());

        table.setComponentPopupMenu(popup);

        table.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            onRowSelected();
        });

        JPanel searchBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 6));
        JButton applyFilter = new JButton("Filter");
        JButton resetFilter = new JButton("Reset");
        searchBar.add(new JLabel("Search/Filter:"));
        searchBar.add(filter);
        searchBar.add(applyFilter);
        searchBar.add(resetFilter);

        applyFilter.addActionListener(e -> applyFilter());
        resetFilter.addActionListener(e -> {
            filter.setText("");
            tableModel.setData(AppState.get().lastResults);
            updatePageInfo();
            applyColumnWidths();
        });

        JPanel pager = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 6));
        JButton prev = new JButton("◀ Prev");
        JButton next = new JButton("Next ▶");
        pager.add(prev);
        pager.add(next);
        pager.add(pageInfo);

        prev.addActionListener(e -> { tableModel.prevPage(); updatePageInfo(); });
        next.addActionListener(e -> { tableModel.nextPage(); updatePageInfo(); });

        tableModel.setPageSize(25);

        JPanel leftTop = new JPanel(new BorderLayout());
        leftTop.add(searchBar, BorderLayout.NORTH);
        leftTop.add(pager, BorderLayout.SOUTH);

        JPanel left = new JPanel(new BorderLayout(6,6));
        left.add(leftTop, BorderLayout.NORTH);
        left.add(new JScrollPane(table), BorderLayout.CENTER);

        previewPath.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        previewPath.setEditable(false);
        previewPath.setLineWrap(true);
        previewPath.setWrapStyleWord(true);
        previewPath.setRows(3);

        preview.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        preview.setEditable(false);

        JButton copyPrettyGraphql = new JButton("Copy GraphQL (pretty)");
        JButton copyBodyJson = new JButton("Copy body (JSON)");
        JButton copyPath = new JButton("Copy path");

        copyPrettyGraphql.addActionListener(e -> copySelectedGraphqlPretty());
        copyBodyJson.addActionListener(e -> copySelectedBody());
        copyPath.addActionListener(e -> {
            String txt = previewPath.getText();
            if (txt != null && !txt.isBlank()) {
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(txt), null);
                showStatus("Copied path.", false);
            }
        });

        JPanel previewToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 6));
        previewToolbar.add(copyPath);
        previewToolbar.add(copyPrettyGraphql);
        previewToolbar.add(copyBodyJson);

        JPanel right = new JPanel(new BorderLayout(6,6));
        right.setBorder(BorderFactory.createTitledBorder("Selected path: preview"));
        right.add(previewToolbar, BorderLayout.NORTH);

        JPanel pathBox = new JPanel(new BorderLayout());
        pathBox.setBorder(BorderFactory.createTitledBorder("Path"));
        pathBox.add(new JScrollPane(previewPath), BorderLayout.CENTER);

        JPanel detailBox = new JPanel(new BorderLayout());
        detailBox.setBorder(BorderFactory.createTitledBorder("Details"));
        detailBox.add(new JScrollPane(preview), BorderLayout.CENTER);

        JPanel rightInner = new JPanel(new BorderLayout(6,6));
        rightInner.add(pathBox, BorderLayout.NORTH);
        rightInner.add(detailBox, BorderLayout.CENTER);

        right.add(rightInner, BorderLayout.CENTER);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left, right);

        // Keep Paths area larger than Preview (better balance)
        split.setResizeWeight(0.72);
        split.setDividerLocation(0.72);

        // Prevent preview dominating when resizing
        left.setMinimumSize(new Dimension(620, 300));
        right.setMinimumSize(new Dimension(420, 300));
        left.setPreferredSize(new Dimension(820, 600));
        right.setPreferredSize(new Dimension(520, 600));
JPanel bottom = new JPanel(new BorderLayout());
        bottom.add(status, BorderLayout.WEST);

        add(controls, BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);

        // Ensure divider location applies after layout
        SwingUtilities.invokeLater(() -> split.setDividerLocation(0.72));
        add(bottom, BorderLayout.SOUTH);

        setBorder(BorderFactory.createEmptyBorder(8,8,8,8));

        updatePageInfo();
        applyColumnWidths();

        schemaWatcher = new Timer(900, e -> refreshTargetsFromSchema());
        schemaWatcher.setRepeats(true);
        schemaWatcher.start();

        refreshTargetsFromSchema();
    }

    private void refreshTargetsFromSchema() {
        long rev = AppState.get().schemaRevision;
        if (rev == lastTargetsRev) return;

        String schemaJson = AppState.get().schemaJson;
        if (schemaJson == null || schemaJson.trim().isEmpty()) return;

        lastTargetsRev = rev;

        SwingWorker<SchemaIndex, Void> w = new SwingWorker<>() {
            @Override protected SchemaIndex doInBackground() throws Exception {
                return SchemaLoader.loadFromIntrospectionJson(schemaJson);
            }

            @Override protected void done() {
                try {
                    SchemaIndex schema = get();
                    refreshTargetChoices(schema);
                } catch (Exception ignored) {
                }
            }
        };
        w.execute();
    }

    private void clearResults() {
        AppState.get().lastResults.clear();
        tableModel.setData(new ArrayList<>());
        preview.setText("");
        previewPath.setText("");
        updatePageInfo();
        applyColumnWidths();
        showStatus("Cleared results.", false);
    }

    private void onRun(boolean pathsOnly) {
        String schemaJson = AppState.get().schemaJson;
        String target = getTargetText();

        if (Strings.isBlank(schemaJson)) {
            JOptionPane.showMessageDialog(this, "Schema is empty. Go to Schema tab and load/paste it first.",
                    "Missing schema", JOptionPane.ERROR_MESSAGE);
            return;
        }
        if (Strings.isBlank(target)) {
            JOptionPane.showMessageDialog(this, "Target type is empty.", "Missing target", JOptionPane.ERROR_MESSAGE);
            return;
        }

        AppState.get().targetType = target;

        int md = (Integer) maxDepth.getValue();
        int sd = (Integer) selectionDepth.getValue();
        boolean includeArgs = includeRequiredArgs.isSelected();

        try {
            SchemaIndex schema = SchemaLoader.loadFromIntrospectionJson(schemaJson);
            refreshTargetChoices(schema);

            List<List<Segment>> paths = PathFinder.findAllPaths(schema, target, md);

            List<PathRow> rows = new ArrayList<>();
            int i = 1;
            for (List<Segment> p : paths) {
                Segment root = p.get(0);
                String pathText = PathFinder.formatPathText(p);
                BuiltQuery built = pathsOnly ? null : QueryGenerator.buildQuery(schema, target, p, i, sd, includeArgs);
                rows.add(new PathRow(i, root.fieldName, p.size(), root.hasRequiredArgs, pathText, built));
                i++;
            }

            AppState.get().lastResults = rows;
            tableModel.setData(rows);
            preview.setText("");
            previewPath.setText("");
            updatePageInfo();
            applyColumnWidths();

            showStatus("Found " + rows.size() + " path(s) to reach '" + target + "'.", false);

        } catch (IllegalArgumentException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void refreshTargetChoices(SchemaIndex schema) {
        try {
            Object selected = targetType.getSelectedItem();
            String selectedText = selected == null ? "" : selected.toString();

            List<String> items = new ArrayList<>();
            for (String name : schema.types.keySet()) {
                if (name == null) continue;
                if (name.startsWith("__")) continue;
                GqlTypeDef def = schema.types.get(name);
                if (def == null) continue;
                if ("OBJECT".equals(def.kind) || "INTERFACE".equals(def.kind)) {
                    items.add(name);
                }
            }
            items.sort(Comparator.naturalOrder());

            DefaultComboBoxModel<String> model = new DefaultComboBoxModel<>(items.toArray(new String[0]));
            targetType.setModel(model);
            targetType.setEditable(true);
            applyLeftArrow(targetType);

            if (!Strings.isBlank(selectedText)) {
                targetType.setSelectedItem(selectedText);
            } else if (!Strings.isBlank(AppState.get().targetType)) {
                targetType.setSelectedItem(AppState.get().targetType);
            }
        } catch (Exception ignored) {
        }
    }

    private String getTargetText() {
        Object item = targetType.getEditor() != null ? targetType.getEditor().getItem() : targetType.getSelectedItem();
        return item == null ? "" : item.toString().trim();
    }

    private void updatePageInfo() {
        pageInfo.setText("Page " + (tableModel.getPageIndex()+1) + "/" + tableModel.getPageCount());
    }

    private void applyColumnWidths() {
        if (table.getColumnModel().getColumnCount() < 5) return;

        table.getColumnModel().getColumn(0).setMinWidth(55);
        table.getColumnModel().getColumn(0).setMaxWidth(70);

        table.getColumnModel().getColumn(2).setMinWidth(120);
        table.getColumnModel().getColumn(2).setMaxWidth(180);

        table.getColumnModel().getColumn(3).setMinWidth(60);
        table.getColumnModel().getColumn(3).setMaxWidth(80);

        table.getColumnModel().getColumn(4).setMinWidth(140);
        table.getColumnModel().getColumn(4).setMaxWidth(170);

        table.getColumnModel().getColumn(1).setPreferredWidth(900);
    }

    private void installPathTooltipRenderer() {
        DefaultTableCellRenderer r = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                if (column == 1) {
                    String text = value == null ? "" : value.toString();
                    if (c instanceof JComponent jc) {
                        jc.setToolTipText(text);
                    }
                }
                return c;
            }
        };
        table.getColumnModel().getColumn(1).setCellRenderer(r);
    }

    private void onRowSelected() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) return;
        int modelRow = table.convertRowIndexToModel(viewRow);
        PathRow r = tableModel.getRowAt(modelRow);
        if (r == null) return;

        previewPath.setText(r.pathText);
        previewPath.setCaretPosition(0);

        if (r.builtQuery != null) {
            BurpBody body = new BurpBody(r.builtQuery.query, r.builtQuery.operationName, r.builtQuery.variables);

            StringBuilder sb = new StringBuilder();
            sb.append("BURP BODY (JSON)\n");
            sb.append(Json.toPrettyString(body)).append("\n\n");
            sb.append("GRAPHQL (pretty)\n");
            sb.append(r.builtQuery.query.replace("\\n", "\n"));

            preview.setText(sb.toString());
        } else {
            preview.setText("This run used 'Show only paths'. No queries were generated.");
        }

        preview.setCaretPosition(0);
    }

    private void applyFilter() {
        String q = filter.getText().trim().toLowerCase();
        if (q.isEmpty()) {
            tableModel.setData(AppState.get().lastResults);
            updatePageInfo();
            applyColumnWidths();
            return;
        }
        List<PathRow> src = AppState.get().lastResults;
        List<PathRow> out = new ArrayList<>();
        for (PathRow r : src) {
            String hay = (r.pathText + " " + r.rootField + " " + r.depth + " " + (r.hasRequiredArgs ? "yes" : "no")).toLowerCase();
            if (hay.contains(q)) out.add(r);
        }
        tableModel.setData(out);
        updatePageInfo();
        applyColumnWidths();
        showStatus("Filter applied (" + out.size() + " rows).", false);
    }

    private void copySelectedBody() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) return;
        int modelRow = table.convertRowIndexToModel(viewRow);
        PathRow r = tableModel.getRowAt(modelRow);
        if (r == null || r.builtQuery == null) return;

        String body = BurpRequestBuilder.buildJsonBody(r.builtQuery);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(body), null);
        showStatus("Copied body JSON to clipboard.", false);
    }

    private void copySelectedGraphqlPretty() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) return;
        int modelRow = table.convertRowIndexToModel(viewRow);
        PathRow r = tableModel.getRowAt(modelRow);
        if (r == null || r.builtQuery == null) return;

        String pretty = r.builtQuery.query.replace("\\n", "\n");
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(pretty), null);
        showStatus("Copied pretty GraphQL to clipboard.", false);
    }

    private void sendSelectedToRepeater() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) return;
        int modelRow = table.convertRowIndexToModel(viewRow);
        PathRow r = tableModel.getRowAt(modelRow);
        if (r == null || r.builtQuery == null) return;

        GeneralConfig cfg = AppState.get().config;
        if (Strings.isBlank(cfg.host) || Strings.isBlank(cfg.scheme) || Strings.isBlank(cfg.endpointPath)) {
            JOptionPane.showMessageDialog(this, "General Config is incomplete (scheme/host/endpoint).",
                    "Config error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        String http = BurpRequestBuilder.buildHttpRequest(cfg, r.builtQuery);

        String url = cfg.scheme + "://" + cfg.host + (needsPort(cfg) ? ":" + cfg.port : "");
        HttpService service = HttpService.httpService(url);
        HttpRequest req = HttpRequest.httpRequest(service, http);

        MontoyaApi api = GqlAsaExtension.API;
        if (api == null) {
            JOptionPane.showMessageDialog(this, "Extension API is not ready.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        api.repeater().sendToRepeater(req);
        showStatus("Sent to Repeater.", false);
    }

    private boolean needsPort(GeneralConfig cfg) {
        if ("https".equalsIgnoreCase(cfg.scheme)) return cfg.port != 443;
        if ("http".equalsIgnoreCase(cfg.scheme)) return cfg.port != 80;
        return true;
    }

    private void showStatus(String msg, boolean error) {
        status.setForeground(error ? new Color(160, 0, 0) : new Color(0, 110, 0));
        status.setText(msg);
        statusClear.restart();
    }

    private static void applyLeftArrow(JComboBox<String> cb) {
        cb.setComponentOrientation(ComponentOrientation.RIGHT_TO_LEFT);
        cb.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
                JLabel l = (JLabel) super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                l.setHorizontalAlignment(SwingConstants.LEFT);
                return l;
            }
        });
        try {
            Component ec = cb.getEditor().getEditorComponent();
            if (ec instanceof JTextField tf) {
                tf.setComponentOrientation(ComponentOrientation.LEFT_TO_RIGHT);
                tf.setHorizontalAlignment(SwingConstants.LEFT);
            }
        } catch (Exception ignored) {
        }
    }
    public void onSchemaChanged() {
        // Schema changed: clear results and refresh target list
        clearResults();
        // Force target refresh
        lastTargetsRev = -1;
        refreshTargetsFromSchema();
    }
}
