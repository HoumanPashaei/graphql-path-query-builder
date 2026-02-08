package com.gqlasa.ui.dos;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import com.gqlasa.GqlAsaExtension;
import com.gqlasa.util.Json;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumnModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * DoS Scanner (GraphQL Cop style).
 *
 * Workflow:
 *  - Import a baseline request via context menu (Proxy/Repeater/History/Intruder/...).
 *  - (Optional) Paste Schema SDL in "Schema" tab to enable schema-driven probes and heavy-object selection.
 *  - Run probes and inspect results in the table + request/response viewer.
 */
public class DosScannerPanel extends JPanel {

    private static volatile DosScannerPanel INSTANCE;

    private final MontoyaApi api;

    // Tabs
    private final JTabbedPane mainTabs = new JTabbedPane();

    // --- Schema tab ---
    private JTextArea schemaArea;
    private JButton btnImportSchema;
    private javax.swing.Timer schemaParseTimer;
    private JLabel schemaStatus;
    private JProgressBar schemaProgress;
    private DefaultListModel<FieldCandidate> heavyListModel;
    private JList<FieldCandidate> heavyList;
    private DefaultListModel<String> allTypesModel;
    private JList<String> allTypesList;
    private JCheckBox cbAutoPick;

    private volatile SchemaModel schemaModel;

    // --- Scanner tab ---
    private JButton btnStart;
    private JButton btnStop;
    private JButton btnOptions;
    private JLabel finishedLabel;

    private JTable table;
    private DosTableModel model;

    // Pagination (10 rows per page)
    private JButton btnPrev;
    private JButton btnNext;
    private JLabel pageLabel;
    private int currentPage = 1;
    private boolean sortPotentialDesc = true;

    private HttpRequestEditor reqEd;
    private HttpResponseEditor resEd;

    private JEditorPane detailsPane;
    private JEditorPane examplePane;

    // Data
    private volatile HttpRequestResponse baseline;
    private volatile HttpRequest baselineRequest;
    private volatile HttpResponse baselineResponse;

    private final List<Row> allRows = new ArrayList<>();
    private final List<Row> viewRows = new ArrayList<>();

    private volatile long baselineTimeMs = -1;

    private final AtomicBoolean stopRequested = new AtomicBoolean(false);
    private volatile ExecutorService pool;

    private final Options opt = new Options();

    public DosScannerPanel() {
        super(new BorderLayout());
        INSTANCE = this;
        this.api = GqlAsaExtension.API;

        setBorder(new EmptyBorder(8, 8, 8, 8));
        buildSchemaTab();
        buildScannerTab();

        mainTabs.addTab("Schema", buildSchemaTabPanel());
        mainTabs.addTab("Scanner", buildScannerTabPanel());

        add(mainTabs, BorderLayout.CENTER);
    }

    public static DosScannerPanel getInstance() {
        return INSTANCE;
    }

    /** Called from context menu provider. */
    public 
    void importFromHttpRequestResponse(HttpRequestResponse rr) {
        if (rr == null) return;
        HttpRequest req = rr.request();
        HttpResponse resp = rr.response();

        if (resp == null) {
            try {
                var sent = api.http().sendRequest(req);
                resp = sent.response();
            } catch (Exception ignored) {
            }
        }

        this.baseline = rr;
        this.baselineRequest = req.copyToTempFile();
        this.baselineResponse = (resp == null) ? null : resp.copyToTempFile();

        clearResults();

        // Reset status + show user we are working
        SwingUtilities.invokeLater(() -> {
            finishedLabel.setText("Status: Idle");
            finishedLabel.setBackground(new Color(245, 245, 245));
            finishedLabel.setForeground(Color.DARK_GRAY);
            finishedLabel.setVisible(true);

            // Also fetch schema automatically (best-effort) so Heavy Objects and schema-based tests can run.
            schemaProgress.setVisible(true);
            schemaStatus.setText("Fetching schema via introspection... please wait.");
        });

        // Best-effort: auto introspection fetch, load into Schema tab, then auto-start scan.
        CompletableFuture
                .supplyAsync(() -> tryFetchIntrospectionSchema(this.baselineRequest))
                .whenCompleteAsync((schemaJson, ex) -> SwingUtilities.invokeLater(() -> {
                    try {
                        if (ex == null && !isNullOrBlank(schemaJson)) {
                            schemaArea.setText(schemaJson);
                            schemaArea.setCaretPosition(0);
                            schemaStatus.setText("Schema loaded from introspection.");
                        } else {
                            schemaStatus.setText("Introspection schema not available (continuing without schema).");
                        }
                    } finally {
                        schemaProgress.setVisible(false);

                        // switch to Scanner tab and start automatically
                        mainTabs.setSelectedIndex(1);
                        onStart(new ActionEvent(btnStart, ActionEvent.ACTION_PERFORMED, "auto-start"));
                    }
                }));
    }

    private static boolean isNullOrBlank(String s) {
        return s == null || s.trim().isEmpty();
    }

    /**
     * Best-effort introspection fetch using the imported baseline request.
     * Returns the raw JSON response body (pretty-printed if possible), or null.
     */
    private String tryFetchIntrospectionSchema(HttpRequest baselineReq) {
        if (baselineReq == null) return null;

        try {
            String introspectionQuery = "query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } }";

            // Build JSON body
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("query", introspectionQuery);
            payload.put("operationName", "IntrospectionQuery");
            payload.put("variables", new LinkedHashMap<String, Object>());
            String body = Json.stringify(payload);

            HttpRequest req = updateBodyAndHeaders(baselineReq, body, "application/json");
            HttpRequestResponse rr = api.http().sendRequest(req);
            HttpResponse resp = rr.response();
            if (resp == null) return null;

            String text = resp.bodyToString();
            if (isNullOrBlank(text)) return null;

            // Try to pretty print JSON if it parses
            try {
                Object parsed = Json.parse(text);
                if (parsed != null) {
                    return Json.toPrettyString(parsed);
                }
            } catch (Exception ignored) {
            }

            return text;
        } catch (Exception e) {
            return null;
        }
    }

    // ---------------------------
    // UI: Schema tab
    // ---------------------------

    private void buildSchemaTab() {
        schemaArea = new JTextArea();
        schemaArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        schemaArea.setLineWrap(true);
        schemaArea.setWrapStyleWord(true);

        btnImportSchema = new JButton("Import schema file");
        btnImportSchema.addActionListener(e -> onImportSchemaFile());

        // Auto-parse schema with a small debounce to avoid parsing on every keystroke
        schemaParseTimer = new javax.swing.Timer(450, e -> parseSchemaNow());
        schemaParseTimer.setRepeats(false);
        schemaArea.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            private void schedule() { schemaParseTimer.restart(); }
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { schedule(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { schedule(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { schedule(); }
        });

        schemaStatus = new JLabel("Paste GraphQL Schema SDL or introspection JSON (optional).\n");

        schemaProgress = new JProgressBar();
        schemaProgress.setIndeterminate(true);
        schemaProgress.setVisible(false);

        heavyListModel = new DefaultListModel<>();
        heavyList = new JList<>(heavyListModel);
        heavyList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        heavyList.setCellRenderer(new DefaultListCellRenderer(){
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (value instanceof FieldCandidate fc) {
                    setText(fc.field + " : " + fc.returnType + (fc.hasPaginationArgs ? "  (pagination args)" : ""));
                }
                return this;
            }
        });

        cbAutoPick = new JCheckBox("Auto-pick top candidates", true);

        allTypesModel = new DefaultListModel<>();
        allTypesList = new JList<>(allTypesModel);
        allTypesList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
    }

    private JPanel buildSchemaTabPanel() {
        JPanel root = new JPanel(new BorderLayout(8, 8));

        JPanel top = new JPanel(new BorderLayout(8, 0));
        JPanel statusWrap = new JPanel(new BorderLayout(6, 0));
        statusWrap.add(schemaStatus, BorderLayout.CENTER);
        statusWrap.add(schemaProgress, BorderLayout.EAST);
        top.add(statusWrap, BorderLayout.CENTER);

        JPanel topRight = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        topRight.add(btnImportSchema);
        top.add(topRight, BorderLayout.EAST);

        JPanel right = new JPanel(new GridLayout(2, 1, 8, 8));
        right.add(wrapTitled(new JScrollPane(heavyList), "Heavy Objects - Candidates (select fields to test)"));
        right.add(wrapTitled(new JScrollPane(allTypesList), "All Object/Type names (select to help targeting)"));

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                wrapTitled(new JScrollPane(schemaArea), "Schema"),
                right
        );
        split.setResizeWeight(0.65);

        JPanel bottom = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        bottom.add(cbAutoPick);

        root.add(top, BorderLayout.NORTH);
        root.add(split, BorderLayout.CENTER);
        root.add(bottom, BorderLayout.SOUTH);
        return root;
    }


    private void onImportSchemaFile() {
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Select GraphQL schema SDL file");
        int res = fc.showOpenDialog(this);
        if (res != JFileChooser.APPROVE_OPTION) return;
        try {
            schemaProgress.setVisible(true);
            schemaStatus.setText("Loading schema file... please wait.");
            java.nio.file.Path p = fc.getSelectedFile().toPath();
            String content = java.nio.file.Files.readString(p, java.nio.charset.StandardCharsets.UTF_8);
            schemaArea.setText(content);
            // parse will be triggered by document listener
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Failed to read schema file: " + ex.getMessage(), "Schema import", JOptionPane.ERROR_MESSAGE);
        } finally {
            schemaProgress.setVisible(false);
        }
    }

    private void parseSchemaNow() {
        String sdl = schemaArea.getText();
        if (sdl == null || sdl.isBlank()) {
            schemaModel = null;
            heavyListModel.clear();
            allTypesModel.clear();
            schemaStatus.setText("Schema cleared.");
            return;
        }

        // Parse in background to avoid blocking the UI on large schemas.
        schemaProgress.setVisible(true);
        schemaStatus.setText("Parsing schema... please wait.");
        final String input = sdl;
        SwingWorker<SchemaModel, Void> worker = new SwingWorker<>() {
            @Override
            protected SchemaModel doInBackground() {
                return SchemaModel.tryParse(input);
            }

            @Override
            protected void done() {
                try {
                    SchemaModel sm = get();
                    schemaModel = sm;

                    heavyListModel.clear();
                    allTypesModel.clear();

                    if (sm == null || sm.types.isEmpty()) {
                        schemaStatus.setText("Could not parse schema. Provide SDL or an Introspection JSON response.");
                        return;
                    }

                    // All types list (excluding introspection built-ins)
                    for (String tn : sm.types.keySet()) {
                        if (tn == null) continue;
                        if (tn.startsWith("__")) continue;
                        allTypesModel.addElement(tn);
                    }

                    List<FieldCandidate> candidates = sm.pickHeavyCandidates(20);
                    for (FieldCandidate fc : candidates) heavyListModel.addElement(fc);

                    if (cbAutoPick.isSelected() && !candidates.isEmpty()) {
                        int toSelect = Math.min(3, candidates.size());
                        int[] idx = new int[toSelect];
                        for (int i = 0; i < toSelect; i++) idx[i] = i;
                        heavyList.setSelectedIndices(idx);
                    }

                    schemaStatus.setText("Schema parsed. Root query type: " + sm.queryTypeName + ". Types: " + sm.types.size() + ", candidates: " + candidates.size());
                } catch (Exception ex) {
                    schemaModel = null;
                    heavyListModel.clear();
                    allTypesModel.clear();
                    schemaStatus.setText("Could not parse schema. Provide SDL or an Introspection JSON response.");
                } finally {
                    schemaProgress.setVisible(false);
                }
            }
        };
        worker.execute();
    }

    // ---------------------------
    // UI: Scanner tab
    // ---------------------------

    private JPanel scannerRoot;

    /**
     * Set sensible fixed column widths because AUTO_RESIZE_OFF is enabled.
     */
    private void setColumnWidths() {
        try {
            int[] widths = new int[]{
                    55,   // Index
                    80,   // Potential
                    220,  // Test
                    95,   // Status code
                    140,  // Response Time (ms)
                    180,  // ΔTime vs Baseline (ms)
                    140,  // Response Length
                    120,  // Payload Size
                    320,  // Error
                    90    // Timeout
            };
            TableColumnModel cm = table.getColumnModel();
            for (int i = 0; i < widths.length && i < cm.getColumnCount(); i++) {
                cm.getColumn(i).setPreferredWidth(widths[i]);
            }
        } catch (Exception ignored) {
            // Best-effort only.
        }
    }

    private void sortAllRowsByPotential(boolean potentialYesFirst) {
        allRows.sort((a, b) -> {
            int pa = a.potential ? 1 : 0;
            int pb = b.potential ? 1 : 0;
            int cmp = Integer.compare(pa, pb);
            if (potentialYesFirst) cmp = -cmp;
            if (cmp != 0) return cmp;
            // Stable secondary order: newest first (higher index) to surface latest runs.
            return Integer.compare(b.index, a.index);
        });
    }

    private void buildScannerTab() {
        btnStart = new JButton("Start");
        btnStart.addActionListener(this::onStart);

        btnStop = new JButton("Stop");
        btnStop.setEnabled(false);
        btnStop.addActionListener(e -> requestStop());

        btnOptions = new JButton("Options");
        btnOptions.addActionListener(e -> showOptionsMenu());

        finishedLabel = new JLabel("Status: Idle");
        finishedLabel.setOpaque(true);
        finishedLabel.setBorder(new EmptyBorder(4, 8, 4, 8));
        finishedLabel.setBackground(new Color(245, 245, 245));
        finishedLabel.setForeground(Color.DARK_GRAY);

        // Table
        model = new DosTableModel(viewRows);
        table = new JTable(model);
        table.setFillsViewportHeight(true);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        installCellRenderer(table);

        table.setIntercellSpacing(new Dimension(12, 4));
        table.setRowHeight(22);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        setColumnWidths();

        table.getTableHeader().addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent e) {
                int col = table.columnAtPoint(e.getPoint());
                if (col == 1) { // Potential
                    sortPotentialDesc = !sortPotentialDesc;
                    sortAllRowsByPotential(sortPotentialDesc);
                    currentPage = 1;
                    refreshPage();
                }
            }
        });

        // Pagination controls
        btnPrev = new JButton("Prev");
        btnNext = new JButton("Next");
        pageLabel = new JLabel("Page 1");
        btnPrev.addActionListener(e -> { if (currentPage > 1) { currentPage--; refreshPage(); }});
        btnNext.addActionListener(e -> { if (currentPage < maxPage()) { currentPage++; refreshPage(); }});

        // Editors
        try {
            reqEd = api.userInterface().createHttpRequestEditor();
            resEd = api.userInterface().createHttpResponseEditor();
        } catch (Exception ex) {
            reqEd = null;
            resEd = null;
        }

        detailsPane = new JEditorPane("text/html", "");
        detailsPane.setEditable(false);
        examplePane = new JEditorPane("text/html", "");
        examplePane.setEditable(false);

        table.getSelectionModel().addListSelectionListener(this::onRowSelected);

        // Context menu
        JPopupMenu rowMenu = new JPopupMenu();
        JMenuItem miRepeater = new JMenuItem("Send to Repeater");
        miRepeater.addActionListener(e -> sendSelectedToRepeater());
        JMenuItem miIntruder = new JMenuItem("Send to Intruder");
        miIntruder.addActionListener(e -> sendSelectedToIntruder());
        rowMenu.add(miRepeater);
        rowMenu.add(miIntruder);
        table.setComponentPopupMenu(rowMenu);
    }

    private JPanel buildScannerTabPanel() {
        scannerRoot = new JPanel(new BorderLayout(8, 8));

        // Top-right config row (no import hint)
        JPanel top = new JPanel(new BorderLayout());
        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        right.add(btnStart);
        right.add(btnStop);
        right.add(btnOptions);
        top.add(right, BorderLayout.EAST);

        finishedLabel.setFont(finishedLabel.getFont().deriveFont(Font.BOLD));
        // green
        finishedLabel.setForeground(new Color(0, 128, 0));
        top.add(finishedLabel, BorderLayout.WEST);

        scannerRoot.add(top, BorderLayout.NORTH);

        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setPreferredSize(new Dimension(950, 260));

        JPanel pager = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        pager.add(btnPrev);
        pager.add(btnNext);
        pager.add(pageLabel);

        JPanel tableWrap = new JPanel(new BorderLayout(0, 6));
        tableWrap.add(tableScroll, BorderLayout.CENTER);
        tableWrap.add(pager, BorderLayout.SOUTH);

        // Details tabs (two pages)
        JTabbedPane detailsTabs = new JTabbedPane();
        JScrollPane detailsScroll = new JScrollPane(detailsPane);
        detailsScroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        JScrollPane exampleScroll = new JScrollPane(examplePane);
        exampleScroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        detailsTabs.addTab("<html><b>Details</b></html>", detailsScroll);
        detailsTabs.addTab("<html><b>Example</b></html>", exampleScroll);
        JPanel detailsWrap = wrapTitled(detailsTabs, "Details");
        detailsWrap.setPreferredSize(new Dimension(420, 260));

        // Request/Response bottom
        Component reqUi = (reqEd == null) ? new JScrollPane(new JTextArea("Request viewer unavailable.")) : reqEd.uiComponent();
        Component resUi = (resEd == null) ? new JScrollPane(new JTextArea("Response viewer unavailable.")) : resEd.uiComponent();
        JPanel rr = new JPanel(new GridLayout(1, 2, 8, 0));
        rr.add(wrapTitled(reqUi, "Request"));
        rr.add(wrapTitled(resUi, "Response"));

        JSplitPane topSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, tableWrap, detailsWrap);
        topSplit.setResizeWeight(0.75);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, topSplit, rr);
        mainSplit.setResizeWeight(0.58);

        scannerRoot.add(mainSplit, BorderLayout.CENTER);
        return scannerRoot;
    }

    // ---------------------------
    // Run
    // ---------------------------

    private void onStart(ActionEvent e) {
        if (baselineRequest == null) {
            JOptionPane.showMessageDialog(this,
                    "No baseline request imported.\n\nRight click a GraphQL request → GQL-ASA → Send to DoS Scanner.",
                    "Baseline required",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        clearResults();
        stopRequested.set(false);
        finishedLabel.setText("Status: Running — please wait until the scan finishes.");
        finishedLabel.setBackground(new Color(220, 235, 255));
        finishedLabel.setForeground(new Color(25, 60, 120));
        finishedLabel.setVisible(true);

        btnStart.setEnabled(false);
        btnStop.setEnabled(true);

        pool = Executors.newFixedThreadPool(opt.concurrency);

        CompletableFuture
                .supplyAsync(this::sendBaseline, pool)
                .thenRunAsync(this::runAllProbes, pool)
                .whenCompleteAsync((v, ex) -> SwingUtilities.invokeLater(() -> {
                    btnStart.setEnabled(true);
                    btnStop.setEnabled(false);
                    shutdownPool();

                    if (ex != null) {
                        finishedLabel.setText("Status: Finished (error)");
                        finishedLabel.setBackground(new Color(255, 225, 225));
                        finishedLabel.setForeground(new Color(140, 0, 0));
                    } else if (stopRequested.get()) {
                        finishedLabel.setText("Status: Stopped");
                        finishedLabel.setBackground(new Color(255, 245, 210));
                        finishedLabel.setForeground(new Color(120, 80, 0));
                    } else {
                        finishedLabel.setText("Status: Finished");
                        finishedLabel.setBackground(new Color(220, 245, 220));
                        finishedLabel.setForeground(new Color(0, 110, 0));
                    }
                    finishedLabel.setVisible(true);
                }), pool);
    }

    private void runAllProbes() {
        if (stopRequested.get()) return;

        ParsedGraphql pg = parseGraphqlFromRequest(baselineRequest);
        String firstField = guessFirstField(pg.query);
        if (firstField == null) firstField = "__typename";

        // Alias overloading (variants)
        if (opt.testAliasOverloading) {
            for (int n : iterRange(opt.aliasMin, opt.aliasMax, opt.aliasStep)) {
                if (stopRequested.get()) break;
                String q = buildAliasOverloadingQuery(firstField, n);
                sendProbe("Alias Overloading (" + n + ")", q, pg.variables,
                        buildDetailsAndExample(
                                detailsAlias(firstField, n),
                                exampleAlias(firstField, n)
                        ));
            }
        }

        // Field duplication
        if (opt.testFieldDuplication) {
            for (int n : iterRange(opt.dupMin, opt.dupMax, opt.dupStep)) {
                if (stopRequested.get()) break;
                String q = buildFieldDuplicationQuery(firstField, n);
                sendProbe("Field Duplication (" + n + ")", q, pg.variables,
                        buildDetailsAndExample(
                                detailsDup(firstField, n),
                                exampleDup(firstField, n)
                        ));
            }
        }

        // Directives overloading
        if (opt.testDirectivesOverloading) {
            for (int n : iterRange(opt.directiveMin, opt.directiveMax, opt.directiveStep)) {
                if (stopRequested.get()) break;
                String q = buildDirectivesOverloadingQuery(firstField, n);
                sendProbe("Directives Overloading (" + n + ")", q, pg.variables,
                        buildDetailsAndExample(
                                detailsDirectives(firstField, n),
                                exampleDirectives(firstField, n)
                        ));
            }
        }

        // Batch queries
        if (opt.testBatchQueries) {
            for (int n : iterRange(opt.batchMin, opt.batchMax, opt.batchStep)) {
                if (stopRequested.get()) break;
                sendBatchProbe("Batch Queries (" + n + ")", pg, n,
                        buildDetailsAndExample(detailsBatch(n), exampleBatch(n)));
            }
        }

        // Introspection nesting
        if (opt.testIntrospectionNesting) {
            for (int d : iterRange(opt.introspectionMinDepth, opt.introspectionMaxDepth, opt.introspectionStep)) {
                if (stopRequested.get()) break;
                String q = buildIntrospectionNestingQuery(d);
                sendProbe("Introspection nesting (" + d + ")", q, Map.of(),
                        buildDetailsAndExample(detailsIntrospection(d), exampleIntrospection(d)));
            }
        }

        // Baseline amplification
        if (opt.testBaselineAmplification) {
            sendBaselineAmplification(pg, opt.amplifyBatchSize);
        }

        // Schema-driven probes
        SchemaModel sm = schemaModel;
        if (sm != null) {
            // Query depth / nested selection
            if (opt.testQueryDepth) {
                for (int d : iterRange(opt.depthMin, opt.depthMax, opt.depthStep)) {
                    if (stopRequested.get()) break;
                    String q = sm.buildDepthQuery(d);
                    if (q == null) continue;
                    sendProbe("Query Depth (" + d + ")", q, Map.of(),
                            buildDetailsAndExample(detailsDepth(d), exampleDepth(q)));
                }
            }

            // Fragment explosion / nested fragments
            if (opt.testFragmentExplosion) {
                for (int n : iterRange(opt.fragMin, opt.fragMax, opt.fragStep)) {
                    if (stopRequested.get()) break;
                    String q = sm.buildFragmentExplosionQuery(n);
                    if (q == null) continue;
                    sendProbe("Fragment Explosion (" + n + ")", q, Map.of(),
                            buildDetailsAndExample(detailsFragments(n), exampleFragments(q)));
                }
            }

            // Pagination abuse
            if (opt.testPaginationAbuse) {
                List<FieldCandidate> pagFields = sm.pickPaginationFields(5);
                for (FieldCandidate fc : pagFields) {
                    if (stopRequested.get()) break;
                    String q = sm.buildPaginationAbuseQuery(fc, opt.paginationValue);
                    if (q == null) continue;
                    sendProbe("Pagination Abuse (" + fc.field + ")", q, Map.of(),
                            buildDetailsAndExample(detailsPagination(fc.field, opt.paginationValue), examplePagination(q)));
                }
            }

            // Heavy objects selection
            if (opt.testHeavyObjects) {
                List<FieldCandidate> selected = heavyList.getSelectedValuesList();
                List<FieldCandidate> effective = new ArrayList<>(selected);
                if (cbAutoPick.isSelected()) {
                    for (FieldCandidate fc : sm.pickHeavyCandidates(3)) {
                        if (effective.stream().noneMatch(x -> x.field.equals(fc.field))) effective.add(fc);
                    }
                }

                for (FieldCandidate fc : effective) {
                    if (stopRequested.get()) break;
                    String q = sm.buildHeavyFieldQuery(fc);
                    if (q == null) continue;
                    // amplify by repeating request in a small batch
                    sendHeavyAmplification(fc, q, opt.heavyAmplifyBatch);
                }
            }
        }

        // Variable bomb (does not require schema)
        if (opt.testVariableBomb) {
            sendVariableBomb(pg, opt.variableBombBytes);
        }
    }

    private void sendHeavyAmplification(FieldCandidate fc, String query, int batch) {
        if (stopRequested.get()) return;
        List<Map<String, Object>> arr = new ArrayList<>();
        for (int i = 0; i < batch; i++) {
            arr.add(Map.of(
                    "operationName", "Heavy" + i,
                    "query", query,
                    "variables", Map.of()
            ));
        }
        String body = Json.stringify(arr);
        HttpRequest req = updateBodyAndHeaders(baselineRequest, body, "application/json");

        sendAndRecord("Heavy Objects (" + fc.field + ", batch=" + batch + ")", req,
                buildDetailsAndExample(
                        detailsHeavy(fc.field, batch),
                        exampleHeavy(query)
                ));
    }

    private void sendVariableBomb(ParsedGraphql pg, int bytes) {
        if (stopRequested.get()) return;

        String q = (pg.query == null || pg.query.isBlank()) ? "query { __typename }" : pg.query;

        Map<String, Object> vars = new LinkedHashMap<>();
        int i = 0;
        int per = Math.max(64, Math.min(512, bytes / 40));
        String chunk = "A".repeat(per);
        int total = 0;
        while (total < bytes && i < 500) {
            String k = String.format("v%03d", i++);
            vars.put(k, chunk);
            total += per;
        }

        String body = buildJsonBody(q, null, vars);
        HttpRequest req = updateBodyAndHeaders(baselineRequest, body, "application/json");

        sendAndRecord("Argument/Variable Bomb (" + bytes + " bytes)", req,
                buildDetailsAndExample(detailsVariableBomb(bytes), exampleVariableBomb(q, vars)));
    }

    private Row sendBaseline() {
        if (stopRequested.get()) return null;
        try {
            long t0 = System.nanoTime();
            HttpRequestResponse r = api.http().sendRequest(baselineRequest);
            long ms = (System.nanoTime() - t0) / 1_000_000L;
            HttpResponse resp = r.response();
            int len = (resp == null) ? 0 : resp.body().length();
            int payload = payloadSize(r.request());
            baselineTimeMs = ms;

            Row row = Row.from(nextIndex(), "Baseline", r.request(), resp, ms, len, payload, "", false,
                    buildDetailsAndExample(
                            "<h3>Baseline</h3><p>This row records the baseline latency for the imported request. " +
                                    "It is used to compute ΔTime vs Baseline and to flag Potential DoS rows.</p>",
                            "<p>No example (this is your imported request).</p>"));
            addRow(row);
            return row;
        } catch (Exception ex) {
            Row row = Row.from(nextIndex(), "Baseline", baselineRequest, null, 0, 0, payloadSize(baselineRequest),
                    ex.getClass().getSimpleName() + ": " + ex.getMessage(), false,
                    buildDetailsAndExample("<h3>Baseline failed</h3>", "<p>Check connectivity / auth.</p>"));
            addRow(row);
            return row;
        }
    }

    private void sendProbe(String testName, String query, Map<String, Object> variables, String detailsHtml) {
        if (stopRequested.get()) return;
        String body = buildJsonBody(query, null, variables);
        HttpRequest req = updateBodyAndHeaders(baselineRequest, body, "application/json");
        sendAndRecord(testName, req, detailsHtml);
    }

    private void sendBatchProbe(String testName, ParsedGraphql pg, int batchSize, String detailsHtml) {
        if (stopRequested.get()) return;

        String q = (pg.query == null || pg.query.isBlank()) ? "query { __typename }" : pg.query;
        Map<String, Object> vars = (pg.variables == null) ? Map.of() : pg.variables;

        List<Map<String, Object>> arr = new ArrayList<>();
        for (int i = 0; i < batchSize; i++) {
            arr.add(Map.of(
                    "operationName", "B" + i,
                    "query", q,
                    "variables", vars
            ));
        }
        String body = Json.stringify(arr);
        HttpRequest req = updateBodyAndHeaders(baselineRequest, body, "application/json");
        sendAndRecord(testName, req, detailsHtml);
    }

    private void sendBaselineAmplification(ParsedGraphql pg, int batchSize) {
        if (stopRequested.get()) return;
        String q = (pg.query == null || pg.query.isBlank()) ? "query { __typename }" : pg.query;
        Map<String, Object> vars = (pg.variables == null) ? Map.of() : pg.variables;

        List<Map<String, Object>> arr = new ArrayList<>();
        for (int i = 0; i < batchSize; i++) {
            arr.add(Map.of(
                    "operationName", "Amp" + i,
                    "query", q,
                    "variables", vars
            ));
        }
        String body = Json.stringify(arr);
        HttpRequest req = updateBodyAndHeaders(baselineRequest, body, "application/json");

        sendAndRecord("Baseline Amplification (batch=" + batchSize + ")", req,
                buildDetailsAndExample(detailsAmplification(batchSize), exampleAmplification(q, batchSize)));
    }

    private void sendAndRecord(String testName, HttpRequest req, String detailsHtml) {
        if (stopRequested.get()) return;

        boolean timeout = false;
        String err = "";
        HttpResponse resp = null;
        long ms = 0;

        try {
            Future<HttpRequestResponse> fut = submitSend(req);
            long t0 = System.nanoTime();
            HttpRequestResponse rr;
            try {
                rr = fut.get(opt.timeoutMs, TimeUnit.MILLISECONDS);
            } catch (TimeoutException te) {
                timeout = true;
                fut.cancel(true);
                rr = null;
            }
            ms = (System.nanoTime() - t0) / 1_000_000L;

            if (rr != null) {
                resp = rr.response();
            }
        } catch (Exception ex) {
            err = ex.getClass().getSimpleName() + ": " + ex.getMessage();
        }

        int len = (resp == null) ? 0 : resp.body().length();
        int payload = payloadSize(req);
        long delta = (baselineTimeMs > 0) ? (ms - baselineTimeMs) : 0;
        boolean potential = isPotential(timeout, ms);

        Row row = Row.from(nextIndex(), testName, req, resp, ms, len, payload, err, timeout, detailsHtml);
        row.deltaTimeMs = delta;
        row.potential = potential;

        addRow(row);
    }

    private boolean isPotential(boolean timeout, long responseTimeMs) {
        if (timeout) return true;
        if (baselineTimeMs <= 0) return false;
        if (responseTimeMs >= (long) (baselineTimeMs * opt.potentialTimeMultiplier)) return true;
        return (responseTimeMs - baselineTimeMs) >= opt.potentialAbsoluteIncreaseMs;
    }

    private Future<HttpRequestResponse> submitSend(HttpRequest req) {
        return ((ExecutorService) pool).submit(() -> api.http().sendRequest(req));
    }

    private void requestStop() {
        stopRequested.set(true);
        btnStop.setEnabled(false);
    }

    private void shutdownPool() {
        try {
            if (pool != null) {
                pool.shutdownNow();
                pool = null;
            }
        } catch (Exception ignored) {
        }
    }

    // ---------------------------
    // Row selection -> viewers + details
    // ---------------------------

    private void onRowSelected(ListSelectionEvent e) {
        if (e.getValueIsAdjusting()) return;
        int r = table.getSelectedRow();
        if (r < 0 || r >= viewRows.size()) return;
        Row row = viewRows.get(r);

        if (reqEd != null && row.request != null) reqEd.setRequest(row.request);
        if (resEd != null) {
            if (row.response != null) resEd.setResponse(row.response);
            else resEd.setResponse(HttpResponse.httpResponse(ByteArray.byteArray(new byte[0])));
        }

        // split stored HTML into details + example
        String[] parts = splitDetails(row.detailsHtml);
        detailsPane.setText(parts[0]);
        examplePane.setText(parts[1]);
        detailsPane.setCaretPosition(0);
        examplePane.setCaretPosition(0);
    }

    private static String[] splitDetails(String combinedHtml) {
        if (combinedHtml == null) return new String[]{"", ""};
        int marker = combinedHtml.indexOf("<!--EXAMPLE-->");
        if (marker < 0) return new String[]{combinedHtml, ""};
        String a = combinedHtml.substring(0, marker);
        String b = combinedHtml.substring(marker + "<!--EXAMPLE-->".length());
        return new String[]{a, b};
    }

    // ---------------------------
    // Pagination + model
    // ---------------------------

    private void clearResults() {
        synchronized (allRows) {
            allRows.clear();
        }
        currentPage = 1;
        refreshPage();
        baselineTimeMs = -1;

        SwingUtilities.invokeLater(() -> {
            detailsPane.setText("");
            examplePane.setText("");
            if (reqEd != null) reqEd.setRequest(HttpRequest.httpRequest(ByteArray.byteArray(new byte[0])));
            if (resEd != null) resEd.setResponse(HttpResponse.httpResponse(ByteArray.byteArray(new byte[0])));
        });
    }

    private void addRow(Row row) {
        synchronized (allRows) {
            allRows.add(row);
        }
        SwingUtilities.invokeLater(() -> {
            refreshPage();
            // auto-select first row if none
            if (table.getSelectedRow() < 0 && !viewRows.isEmpty()) {
                table.setRowSelectionInterval(0, 0);
            }
        });
    }

    private int maxPage() {
        synchronized (allRows) {
            return Math.max(1, (int) Math.ceil(allRows.size() / 10.0));
        }
    }

    private void refreshPage() {
        synchronized (allRows) {
            viewRows.clear();
            int start = (currentPage - 1) * 10;
            int end = Math.min(allRows.size(), start + 10);
            if (start >= end) {
                currentPage = Math.max(1, maxPage());
                start = (currentPage - 1) * 10;
                end = Math.min(allRows.size(), start + 10);
            }
            for (int i = start; i < end; i++) viewRows.add(allRows.get(i));
        }
        model.fireTableDataChanged();
        pageLabel.setText("Page " + currentPage + " / " + maxPage());
        btnPrev.setEnabled(currentPage > 1);
        btnNext.setEnabled(currentPage < maxPage());
    }

    private int nextIndex() {
        synchronized (allRows) {
            return allRows.size() + 1;
        }
    }

    private static void installCellRenderer(JTable t) {
        DefaultTableCellRenderer r = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                setHorizontalAlignment(SwingConstants.LEFT);

                if (table.getModel() instanceof DosTableModel m) {
                    Row rr = m.rows.get(row);
                    Font f = c.getFont();
                    if (rr != null && rr.potential) {
                        c.setFont(f.deriveFont(Font.BOLD));
                    } else {
                        c.setFont(f.deriveFont(Font.PLAIN));
                    }
                }
                return c;
            }
        };
        for (int i = 0; i < t.getColumnModel().getColumnCount(); i++) {
            t.getColumnModel().getColumn(i).setCellRenderer(r);
        }
    }

    // ---------------------------
    // Options dropdown
    // ---------------------------

    private void showOptionsMenu() {
        JPopupMenu menu = new JPopupMenu();

        // --- Tests toggles
        menu.add(makeSectionLabel("Tests"));
        menu.add(makeToggle("Alias Overloading", opt.testAliasOverloading, v -> opt.testAliasOverloading = v));
        menu.add(makeToggle("Batch Queries", opt.testBatchQueries, v -> opt.testBatchQueries = v));
        menu.add(makeToggle("Field Duplication", opt.testFieldDuplication, v -> opt.testFieldDuplication = v));
        menu.add(makeToggle("Directives Overloading", opt.testDirectivesOverloading, v -> opt.testDirectivesOverloading = v));
        menu.add(makeToggle("Introspection Nesting", opt.testIntrospectionNesting, v -> opt.testIntrospectionNesting = v));
        menu.add(makeToggle("Baseline Amplification", opt.testBaselineAmplification, v -> opt.testBaselineAmplification = v));

        menu.addSeparator();
        menu.add(makeSectionLabel("Schema-driven tests"));
        menu.add(makeToggle("Query Depth (schema)", opt.testQueryDepth, v -> opt.testQueryDepth = v));
        menu.add(makeToggle("Fragment Explosion (schema)", opt.testFragmentExplosion, v -> opt.testFragmentExplosion = v));
        menu.add(makeToggle("Pagination Abuse (schema)", opt.testPaginationAbuse, v -> opt.testPaginationAbuse = v));
        menu.add(makeToggle("Heavy Objects (schema)", opt.testHeavyObjects, v -> opt.testHeavyObjects = v));
        menu.add(makeToggle("Argument/Variable Bomb", opt.testVariableBomb, v -> opt.testVariableBomb = v));

        // --- Runtime
        menu.addSeparator();
        menu.add(makeSectionLabel("Runtime"));
        menu.add(makeIntSpinnerRow("Timeout (ms)", opt.timeoutMs, 1000, 120000, 500, v -> opt.timeoutMs = v));
        menu.add(makeIntSpinnerRow("Concurrency", opt.concurrency, 1, 64, 1, v -> opt.concurrency = v));

        // --- Potential rule
        menu.addSeparator();
        menu.add(makeSectionLabel("Potential rule"));
        menu.add(makeDoubleSpinnerRow("Baseline multiplier", opt.potentialTimeMultiplier, 1.0, 50.0, 0.5, v -> opt.potentialTimeMultiplier = v));
        menu.add(makeLongSpinnerRow("Absolute Δms", opt.potentialAbsoluteIncreaseMs, 0L, 120000L, 250L, v -> opt.potentialAbsoluteIncreaseMs = v));

        // --- Ranges
        menu.addSeparator();
        menu.add(makeSectionLabel("Ranges"));
        menu.add(makeIntSpinnerRow("Alias min", opt.aliasMin, 1, 5000, 1, v -> opt.aliasMin = v));
        menu.add(makeIntSpinnerRow("Alias max", opt.aliasMax, 1, 5000, 5, v -> opt.aliasMax = v));
        menu.add(makeIntSpinnerRow("Alias step", opt.aliasStep, 1, 1000, 1, v -> opt.aliasStep = v));

        menu.add(makeIntSpinnerRow("Dup min", opt.dupMin, 1, 5000, 1, v -> opt.dupMin = v));
        menu.add(makeIntSpinnerRow("Dup max", opt.dupMax, 1, 5000, 5, v -> opt.dupMax = v));
        menu.add(makeIntSpinnerRow("Dup step", opt.dupStep, 1, 1000, 1, v -> opt.dupStep = v));

        menu.add(makeIntSpinnerRow("Directive min", opt.directiveMin, 1, 5000, 1, v -> opt.directiveMin = v));
        menu.add(makeIntSpinnerRow("Directive max", opt.directiveMax, 1, 5000, 5, v -> opt.directiveMax = v));
        menu.add(makeIntSpinnerRow("Directive step", opt.directiveStep, 1, 1000, 1, v -> opt.directiveStep = v));

        menu.add(makeIntSpinnerRow("Batch min", opt.batchMin, 1, 5000, 1, v -> opt.batchMin = v));
        menu.add(makeIntSpinnerRow("Batch max", opt.batchMax, 1, 5000, 5, v -> opt.batchMax = v));
        menu.add(makeIntSpinnerRow("Batch step", opt.batchStep, 1, 1000, 1, v -> opt.batchStep = v));

        menu.add(makeIntSpinnerRow("Introspection depth min", opt.introspectionMinDepth, 1, 200, 1, v -> opt.introspectionMinDepth = v));
        menu.add(makeIntSpinnerRow("Introspection depth max", opt.introspectionMaxDepth, 1, 200, 1, v -> opt.introspectionMaxDepth = v));
        menu.add(makeIntSpinnerRow("Introspection depth step", opt.introspectionStep, 1, 50, 1, v -> opt.introspectionStep = v));

        menu.add(makeIntSpinnerRow("Depth min", opt.depthMin, 1, 200, 1, v -> opt.depthMin = v));
        menu.add(makeIntSpinnerRow("Depth max", opt.depthMax, 1, 200, 1, v -> opt.depthMax = v));
        menu.add(makeIntSpinnerRow("Depth step", opt.depthStep, 1, 50, 1, v -> opt.depthStep = v));

        menu.add(makeIntSpinnerRow("Fragments min", opt.fragMin, 1, 2000, 1, v -> opt.fragMin = v));
        menu.add(makeIntSpinnerRow("Fragments max", opt.fragMax, 1, 2000, 10, v -> opt.fragMax = v));
        menu.add(makeIntSpinnerRow("Fragments step", opt.fragStep, 1, 500, 1, v -> opt.fragStep = v));

        menu.add(makeIntSpinnerRow("Variable bomb bytes", opt.variableBombBytes, 512, 500000, 512, v -> opt.variableBombBytes = v));
        menu.add(makeIntSpinnerRow("Pagination value", opt.paginationValue, 1, 1000000, 100, v -> opt.paginationValue = v));
        menu.add(makeIntSpinnerRow("Amplify batch", opt.amplifyBatchSize, 1, 5000, 1, v -> opt.amplifyBatchSize = v));
        menu.add(makeIntSpinnerRow("Heavy amplify batch", opt.heavyAmplifyBatch, 1, 5000, 1, v -> opt.heavyAmplifyBatch = v));

        // show
        menu.show(btnOptions, 0, btnOptions.getHeight());
    }

    private JMenuItem makeToggle(String title, boolean current, java.util.function.Consumer<Boolean> setter) {
        JCheckBoxMenuItem mi = new JCheckBoxMenuItem(title, current);
        mi.addActionListener(e -> setter.accept(mi.isSelected()));
        return mi;
    }


    private JMenuItem makeSectionLabel(String title) {
        JMenuItem mi = new JMenuItem(title);
        mi.setEnabled(false);
        Font f = mi.getFont();
        mi.setFont(f.deriveFont(Font.BOLD));
        return mi;
    }

    private Component makeIntSpinnerRow(String title, int current, int min, int max, int step, java.util.function.IntConsumer setter) {
        JPanel p = new JPanel(new BorderLayout(8, 0));
        p.setBorder(new EmptyBorder(2, 10, 2, 10));
        JLabel l = new JLabel(title);
        JSpinner sp = new JSpinner(new SpinnerNumberModel(current, min, max, step));
        sp.addChangeListener(e -> {
            try { setter.accept((Integer) sp.getValue()); } catch (Exception ignored) {}
        });
        p.add(l, BorderLayout.WEST);
        p.add(sp, BorderLayout.EAST);
        return p;
    }

    private Component makeLongSpinnerRow(String title, long current, long min, long max, long step, java.util.function.LongConsumer setter) {
        JPanel p = new JPanel(new BorderLayout(8, 0));
        p.setBorder(new EmptyBorder(2, 10, 2, 10));
        JLabel l = new JLabel(title);
        JSpinner sp = new JSpinner(new SpinnerNumberModel(current, min, max, step));
        sp.addChangeListener(e -> {
            try { setter.accept(((Number) sp.getValue()).longValue()); } catch (Exception ignored) {}
        });
        p.add(l, BorderLayout.WEST);
        p.add(sp, BorderLayout.EAST);
        return p;
    }

    private Component makeDoubleSpinnerRow(String title, double current, double min, double max, double step, java.util.function.DoubleConsumer setter) {
        JPanel p = new JPanel(new BorderLayout(8, 0));
        p.setBorder(new EmptyBorder(2, 10, 2, 10));
        JLabel l = new JLabel(title);
        JSpinner sp = new JSpinner(new SpinnerNumberModel(current, min, max, step));
        sp.addChangeListener(e -> {
            try { setter.accept(((Number) sp.getValue()).doubleValue()); } catch (Exception ignored) {}
        });
        p.add(l, BorderLayout.WEST);
        p.add(sp, BorderLayout.EAST);
        return p;
    }

    private JMenuItem makePromptInt(String title, int current, java.util.function.IntConsumer setter) {
        JMenuItem mi = new JMenuItem(title + " = " + current);
        mi.addActionListener(e -> {
            String s = JOptionPane.showInputDialog(this, title, String.valueOf(current));
            if (s == null) return;
            try { setter.accept(Integer.parseInt(s.trim())); } catch (Exception ignored) {}
        });
        return mi;
    }

    private JMenuItem makePromptLong(String title, long current, java.util.function.LongConsumer setter) {
        JMenuItem mi = new JMenuItem(title + " = " + current);
        mi.addActionListener(e -> {
            String s = JOptionPane.showInputDialog(this, title, String.valueOf(current));
            if (s == null) return;
            try { setter.accept(Long.parseLong(s.trim())); } catch (Exception ignored) {}
        });
        return mi;
    }

    private JMenuItem makePromptDouble(String title, double current, java.util.function.DoubleConsumer setter) {
        JMenuItem mi = new JMenuItem(title + " = " + current);
        mi.addActionListener(e -> {
            String s = JOptionPane.showInputDialog(this, title, String.valueOf(current));
            if (s == null) return;
            try { setter.accept(Double.parseDouble(s.trim())); } catch (Exception ignored) {}
        });
        return mi;
    }

    // ---------------------------
    // Burp actions
    // ---------------------------

    private void sendSelectedToRepeater() {
        int r = table.getSelectedRow();
        if (r < 0 || r >= viewRows.size()) return;
        Row row = viewRows.get(r);
        if (row.request == null) return;
        try {
            api.repeater().sendToRepeater(row.request);
        } catch (Exception ignored) {
        }
    }

    private void sendSelectedToIntruder() {
        int r = table.getSelectedRow();
        if (r < 0 || r >= viewRows.size()) return;
        Row row = viewRows.get(r);
        if (row.request == null) return;
        try {
            api.intruder().sendToIntruder(row.request);
        } catch (Exception ignored) {
        }
    }

    // ---------------------------
    // Builders
    // ---------------------------

    private static List<Integer> iterRange(int min, int max, int step) {
        if (step <= 0) step = 1;
        if (max < min) { int t = max; max = min; min = t; }
        List<Integer> out = new ArrayList<>();
        int count = 0;
        for (int v = min; v <= max; v += step) {
            out.add(v);
            if (++count >= 30) break;
        }
        if (out.isEmpty()) out.add(min);
        return out;
    }

    private static String buildAliasOverloadingQuery(String field, int count) {
        StringBuilder sb = new StringBuilder();
        sb.append("query AliasOverloading {\n");
        for (int i = 1; i <= count; i++) {
            sb.append("  a").append(i).append(": ").append(field);
            if (!"__typename".equals(field)) sb.append(" { __typename }");
            sb.append("\n");
        }
        sb.append("}\n");
        return sb.toString();
    }

    private static String buildFieldDuplicationQuery(String field, int count) {
        StringBuilder sb = new StringBuilder();
        sb.append("query FieldDuplication {\n");
        for (int i = 1; i <= count; i++) {
            sb.append("  ").append(field);
            if (!"__typename".equals(field)) sb.append(" { __typename }");
            sb.append("\n");
        }
        sb.append("}\n");
        return sb.toString();
    }

    private static String buildDirectivesOverloadingQuery(String field, int count) {
        StringBuilder sb = new StringBuilder();
        sb.append("query DirectivesOverloading {\n");
        sb.append("  ").append(field);
        for (int i = 0; i < count; i++) sb.append(" @skip(if:false)");
        if (!"__typename".equals(field)) sb.append(" { __typename }");
        sb.append("\n}\n");
        return sb.toString();
    }

    private static String buildIntrospectionNestingQuery(int depth) {
        // Deep nesting of __schema -> types -> ofType ...
        StringBuilder sb = new StringBuilder();
        sb.append("query IntrospectionDeep { __schema { types { name kind ");
        sb.append(buildOfType(depth));
        sb.append(" } } }");
        return sb.toString();
    }

    private static String buildOfType(int depth) {
        StringBuilder sb = new StringBuilder();
        String part = "ofType { kind name ";
        for (int i = 0; i < depth; i++) sb.append(part);
        sb.append("__typename");
        for (int i = 0; i < depth; i++) sb.append(" }");
        return sb.toString();
    }

    // ---------------------------
    // Details / Example (English)
    // ---------------------------

    private static String wrapHtml(String inner) {
        String css = "body{font-family:sans-serif;font-size:12px;}" +
                "h3{margin:6px 0;}" +
                "pre{background:#f6f6f6;padding:8px;border:1px solid #e0e0e0;border-radius:8px;white-space:pre-wrap;word-wrap:break-word;overflow-wrap:anywhere;}" +
                "code{background:#f2f2f2;padding:1px 3px;border-radius:4px;}";
        return "<html><head><style>" + css + "</style></head><body>" + (inner == null ? "" : inner) + "</body></html>";
    }

    private static String buildDetailsAndExample(String detailsHtml, String exampleHtml) {
        return wrapHtml(detailsHtml) + "<!--EXAMPLE-->" + wrapHtml(exampleHtml);
    }

    private static String detailsAlias(String field, int n) {
        return "<h3>Alias Overloading</h3>" +
                "<p>This probe sends a single operation that executes the same resolver multiple times using different aliases." +
                " Servers that do not enforce query complexity limits may spend significant CPU/DB time resolving duplicated selections.</p>" +
                "<ul>" +
                "<li><b>Target field</b>: " + esc(field) + "</li>" +
                "<li><b>Alias count</b>: " + n + "</li>" +
                "<li><b>What to watch</b>: large ΔTime vs Baseline, timeouts, 5xx, or GraphQL errors indicating resource exhaustion.</li>" +
                "</ul>";
    }

    private static String exampleAlias(String field, int n) {
        return "<h3>Example</h3>" +
                "<p>Example query with aliases (" + n + "):</p>" +
                "<pre>" + esc(prettyGraphql(buildAliasOverloadingQuery(field, Math.min(n, 10)))) + "</pre>" +
                "<p>In practice the scanner increases the alias count across a range to observe performance degradation.</p>";
    }

    private static String detailsDup(String field, int n) {
        return "<h3>Field Duplication</h3>" +
                "<p>This probe duplicates the same field multiple times in the same selection set. " +
                "Depending on caching and resolver behavior, it can still trigger repeated execution or expensive response construction.</p>" +
                "<ul><li><b>Field</b>: " + esc(field) + "</li><li><b>Duplicates</b>: " + n + "</li></ul>";
    }

    private static String exampleDup(String field, int n) {
        return "<h3>Example</h3><pre>" + esc(prettyGraphql(buildFieldDuplicationQuery(field, Math.min(n, 10)))) + "</pre>";
    }

    private static String detailsDirectives(String field, int n) {
        return "<h3>Directives Overloading</h3>" +
                "<p>This probe attaches many directives (e.g. <code>@skip</code>) to a field. " +
                "Some GraphQL servers spend extra time evaluating directives repeatedly.</p>" +
                "<ul><li><b>Field</b>: " + esc(field) + "</li><li><b>Directive count</b>: " + n + "</li></ul>";
    }

    private static String exampleDirectives(String field, int n) {
        return "<h3>Example</h3><pre>" + esc(prettyGraphql(buildDirectivesOverloadingQuery(field, Math.min(n, 20)))) + "</pre>";
    }

    private static String detailsBatch(int n) {
        return "<h3>Batch Queries</h3>" +
                "<p>This probe sends a JSON array of operations in a single HTTP request. " +
                "If batching is enabled without proper limits, one request can trigger many executions.</p>" +
                "<ul><li><b>Batch size</b>: " + n + "</li></ul>";
    }

    private static String exampleBatch(int n) {
        return "<h3>Example</h3>" +
                "<p>HTTP body is a JSON array with " + n + " entries (each entry includes <code>query</code> and <code>variables</code>).</p>";
    }

    private static String detailsIntrospection(int d) {
        return "<h3>Circular / Introspection Deep Nesting</h3>" +
                "<p>This probe requests deeply nested <code>ofType</code> chains via introspection. " +
                "Some servers do not restrict nesting, causing excessive processing.</p>" +
                "<ul><li><b>Depth</b>: " + d + "</li></ul>";
    }

    private static String exampleIntrospection(int d) {
        return "<h3>Example</h3><pre>" + esc(prettyGraphql(buildIntrospectionNestingQuery(Math.min(d, 8)))) + "</pre>";
    }

    private static String detailsAmplification(int n) {
        return "<h3>Baseline Amplification</h3>" +
                "<p>This probe repeats the baseline operation in a batch to approximate load amplification. " +
                "It is useful when the baseline touches expensive resolvers (heavy objects).</p>" +
                "<ul><li><b>Batch size</b>: " + n + "</li></ul>";
    }

    private static String exampleAmplification(String q, int n) {
        return "<h3>Example</h3><p>The request body contains an array of the same operation repeated " + n + " times.</p>" +
                "<pre>" + esc(q.length() > 400 ? q.substring(0, 400) + "..." : q) + "</pre>";
    }

    private static String detailsDepth(int d) {
        return "<h3>Query Depth / Nested Selection</h3>" +
                "<p>This probe builds a deeply nested selection path using schema information. " +
                "Servers lacking depth limits may spend disproportionate time walking nested resolvers.</p>" +
                "<ul><li><b>Depth</b>: " + d + "</li></ul>";
    }

    private static String exampleDepth(String query) {
        return "<h3>Example</h3><pre>" + esc(query) + "</pre>";
    }

    private static String detailsFragments(int n) {
        return "<h3>Fragment Explosion / Nested Fragments</h3>" +
                "<p>This probe defines fragments and then spreads them many times to amplify execution/validation work. " +
                "Some servers are vulnerable to fragment expansion costs.</p>" +
                "<ul><li><b>Spreads</b>: " + n + "</li></ul>";
    }

    private static String exampleFragments(String query) {
        return "<h3>Example</h3><pre>" + esc(query) + "</pre>";
    }

    private static String detailsVariableBomb(int bytes) {
        return "<h3>Argument / Variable Bomb</h3>" +
                "<p>This probe sends a very large <code>variables</code> object to stress request parsing and JSON processing. " +
                "Even if variables are unused, some implementations still incur significant overhead.</p>" +
                "<ul><li><b>Approx variables payload</b>: " + bytes + " bytes</li></ul>";
    }

    private static String exampleVariableBomb(String q, Map<String, Object> vars) {
        return "<h3>Example</h3>" +
                "<p>Query is the baseline (or a minimal query), and variables contain many large entries.</p>" +
                "<pre>query (truncated):\n" + esc(q.length() > 300 ? q.substring(0, 300) + "..." : q) + "\n\nvariables keys: " + esc(String.valueOf(vars.keySet().stream().limit(10).toList())) + " ...</pre>";
    }

    private static String detailsPagination(String field, int value) {
        return "<h3>List Size / Pagination Abuse</h3>" +
                "<p>This probe attempts to request excessive page sizes (e.g. <code>first</code>/<code>limit</code>). " +
                "If servers do not cap list sizes, this can cause expensive DB queries and huge responses.</p>" +
                "<ul><li><b>Field</b>: " + esc(field) + "</li><li><b>Value</b>: " + value + "</li></ul>";
    }

    private static String examplePagination(String query) {
        return "<h3>Example</h3><pre>" + esc(query) + "</pre>";
    }

    private static String detailsHeavy(String field, int batch) {
        return "<h3>Heavy Objects</h3>" +
                "<p>This probe targets schema-selected fields that are likely to be expensive (object/list return types). " +
                "It sends a small batch of queries to amplify resolver cost.</p>" +
                "<ul><li><b>Field</b>: " + esc(field) + "</li><li><b>Batch</b>: " + batch + "</li></ul>";
    }

    private static String exampleHeavy(String query) {
        return "<h3>Example</h3><pre>" + esc(query) + "</pre>";
    }

    // ---------------------------
    // HTTP body helpers
    // ---------------------------

    private static int payloadSize(HttpRequest req) {
        try {
            if (req == null) return 0;
            return req.toByteArray().length();
        } catch (Exception e) {
            return 0;
        }
    }

    private static HttpRequest updateBodyAndHeaders(HttpRequest original, String body, String contentType) {
        if (original == null) return null;
        HttpRequest req = original;

        // Remove existing Content-Length (Burp will set it)
        req = removeHeader(req, "Content-Length");

        // Update Content-Type
        req = upsertHeader(req, "Content-Type", contentType);

        // Body
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        return req.withBody(ByteArray.byteArray(bytes));
    }

    private static HttpRequest removeHeader(HttpRequest req, String name) {
        try {
            for (HttpHeader h : req.headers()) {
                if (h.name().equalsIgnoreCase(name)) {
                    return req.withRemovedHeader(h);
                }
            }
            return req;
        } catch (Exception e) {
            return req;
        }
    }

    private static HttpRequest upsertHeader(HttpRequest req, String name, String value) {
        try {
            for (HttpHeader h : req.headers()) {
                if (h.name().equalsIgnoreCase(name)) {
                    return req.withUpdatedHeader(HttpHeader.httpHeader(name, value));
                }
            }
            return req.withAddedHeader(HttpHeader.httpHeader(name, value));
        } catch (Exception e) {
            return req;
        }
    }

    private static String buildJsonBody(String query, String operationName, Map<String, Object> variables) {
        Map<String, Object> m = new LinkedHashMap<>();
        if (operationName != null && !operationName.isBlank()) m.put("operationName", operationName);
        m.put("query", (query == null || query.isBlank()) ? "query { __typename }" : query);
        m.put("variables", (variables == null) ? Map.of() : variables);
        return Json.stringify(m);
    }

    private static ParsedGraphql parseGraphqlFromRequest(HttpRequest req) {
        if (req == null) return new ParsedGraphql(null, Map.of());
        try {
            String body = req.bodyToString();
            if (body == null) return new ParsedGraphql(null, Map.of());
            body = body.trim();

            if (body.startsWith("[")) {
                // take first item
                Object parsed = Json.parse(body);
                if (parsed instanceof List<?> lst && !lst.isEmpty() && lst.get(0) instanceof Map<?,?> mm) {
                    String q = String.valueOf(mm.get("query"));
                    Object vars = mm.get("variables");
                    return new ParsedGraphql(q, castVars(vars));
                }
            }

            Object parsed = Json.parse(body);
            if (parsed instanceof Map<?, ?> map) {
                String q = map.get("query") == null ? null : String.valueOf(map.get("query"));
                Object vars = map.get("variables");
                return new ParsedGraphql(q, castVars(vars));
            }
        } catch (Exception ignored) {
        }
        return new ParsedGraphql(null, Map.of());
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> castVars(Object vars) {
        if (vars instanceof Map<?, ?> m) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (var e : m.entrySet()) {
                out.put(String.valueOf(e.getKey()), e.getValue());
            }
            return out;
        }
        return Map.of();
    }

    private static String guessFirstField(String query) {
        if (query == null) return null;
        // naive: first token after '{'
        int i = query.indexOf('{');
        if (i < 0) return null;
        String tail = query.substring(i + 1);
        Matcher m = Pattern.compile("\\b([_A-Za-z][_0-9A-Za-z]*)\\b").matcher(tail);
        while (m.find()) {
            String s = m.group(1);
            if ("query".equals(s) || "mutation".equals(s) || "subscription".equals(s)) continue;
            if ("fragment".equals(s) || "on".equals(s)) continue;
            return s;
        }
        return null;
    }

    private static JPanel wrapTitled(Component c, String title) {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(BorderFactory.createTitledBorder(title));
        p.add(c, BorderLayout.CENTER);
        return p;
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private static String prettyGraphql(String q) {
        if (q == null) return "";
        String s = q.replace("\r", "").trim();
        StringBuilder out = new StringBuilder();
        int indent = 0;
        boolean inString = false;
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch == '"') {
                out.append(ch);
                // naive toggle (ignores escapes)
                inString = !inString;
                continue;
            }
            if (inString) {
                out.append(ch);
                continue;
            }
            if (ch == '{') {
                out.append(" {\n");
                indent++;
                out.append("  ".repeat(indent));
            } else if (ch == '}') {
                indent = Math.max(0, indent - 1);
                out.append("\n").append("  ".repeat(indent)).append("}");
                // if next isn't end and not newline, add newline
                if (i + 1 < s.length() && s.charAt(i + 1) != '\n') {
                    out.append("\n").append("  ".repeat(indent));
                }
            } else if (ch == '\n') {
                out.append("\n").append("  ".repeat(indent));
            } else if (ch == ' ' || ch == '\t') {
                // collapse excessive spaces
                if (out.length() > 0 && out.charAt(out.length()-1) != ' ' && out.charAt(out.length()-1) != '\n') out.append(' ');
            } else {
                out.append(ch);
            }
        }
        // Replace trailing spaces before newlines with a real newline.
        // NOTE: In regex replacement strings, "\\n" would be interpreted as a literal 'n'.
        return out.toString().replaceAll(" +\\n", "\n").trim();
    }


    // ---------------------------
    // Table model + row
    // ---------------------------

    private static final class Row {
        final int index;
        final String testName;
        final HttpRequest request;
        final HttpResponse response;
        final String statusCode;
        final long responseTimeMs;
        long deltaTimeMs;
        final int responseLength;
        final int payloadSize;
        final String error;
        final boolean timeout;
        boolean potential;
        final String detailsHtml;

        private Row(int index, String testName, HttpRequest request, HttpResponse response,
                    String statusCode, long responseTimeMs, int responseLength, int payloadSize,
                    String error, boolean timeout, String detailsHtml) {
            this.index = index;
            this.testName = testName;
            this.request = request;
            this.response = response;
            this.statusCode = statusCode;
            this.responseTimeMs = responseTimeMs;
            this.responseLength = responseLength;
            this.payloadSize = payloadSize;
            this.error = error;
            this.timeout = timeout;
            this.detailsHtml = detailsHtml;
        }

        static Row from(int index, String testName, HttpRequest request, HttpResponse response,
                        long responseTimeMs, int responseLength, int payloadSize, String error,
                        boolean timeout, String detailsHtml) {
            String sc = "";
            try { if (response != null) sc = String.valueOf(response.statusCode()); } catch (Exception ignored) {}
            return new Row(index, testName, request, response, sc, responseTimeMs, responseLength, payloadSize, error, timeout, detailsHtml);
        }
    }

    private static final class DosTableModel extends AbstractTableModel {
        private final List<Row> rows;

        private final String[] cols = new String[]{
                "Index", "Potential", "Test", "Status code", "Response Time (ms)", "ΔTime vs Baseline (ms)",
                "Response Length", "Payload Size", "Error", "Timeout"
        };

        DosTableModel(List<Row> rows) {
            this.rows = rows;
        }

        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return cols.length; }
        @Override public String getColumnName(int c) { return cols[c]; }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            Row r = rows.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> r.index;
                case 1 -> r.potential ? "Yes" : "No";
                case 2 -> r.testName;
                case 3 -> r.statusCode;
                case 4 -> r.responseTimeMs;
                case 5 -> r.deltaTimeMs;
                case 6 -> r.responseLength;
                case 7 -> r.payloadSize;
                case 8 -> r.error;
                case 9 -> r.timeout ? "Yes" : "No";
                default -> "";
            };
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            return switch (columnIndex) {
                case 0 -> Integer.class;
                case 4, 5 -> Long.class;
                case 6, 7 -> Integer.class;
                default -> String.class;
            };
        }
    }

    private static final class Options {
        int timeoutMs = 8000;
        int concurrency = 2;

        double potentialTimeMultiplier = 3.0;
        long potentialAbsoluteIncreaseMs = 2000;

        boolean testAliasOverloading = true;
        boolean testBatchQueries = true;
        boolean testFieldDuplication = true;
        boolean testDirectivesOverloading = true;
        boolean testIntrospectionNesting = true;
        boolean testBaselineAmplification = true;

        boolean testQueryDepth = true;
        boolean testFragmentExplosion = true;
        boolean testPaginationAbuse = true;
        boolean testHeavyObjects = true;
        boolean testVariableBomb = true;

        int aliasMin = 5, aliasMax = 100, aliasStep = 5;
        int dupMin = 5, dupMax = 100, dupStep = 5;
        int directiveMin = 10, directiveMax = 200, directiveStep = 10;
        int batchMin = 2, batchMax = 50, batchStep = 8;
        int introspectionMinDepth = 5, introspectionMaxDepth = 25, introspectionStep = 5;

        int depthMin = 3, depthMax = 12, depthStep = 3;
        int fragMin = 10, fragMax = 100, fragStep = 15;
        int paginationValue = 10000;

        int amplifyBatchSize = 30;
        int heavyAmplifyBatch = 20;
        int variableBombBytes = 25000;
    }

    private static final class ParsedGraphql {
        final String query;
        final Map<String, Object> variables;

        ParsedGraphql(String query, Map<String, Object> variables) {
            this.query = query;
            this.variables = (variables == null) ? Map.of() : variables;
        }
    }

    // ---------------------------
    // Schema parsing (SDL, minimal)
    // ---------------------------

    private static final Set<String> SCALARS = Set.of("String", "Int", "Float", "Boolean", "ID");

    private static final class FieldCandidate {
        final String field;
        final String returnType;
        final boolean isList;
        final boolean hasPaginationArgs;
        final int score;

        FieldCandidate(String field, String returnType, boolean isList, boolean hasPaginationArgs, int score) {
            this.field = field;
            this.returnType = returnType;
            this.isList = isList;
            this.hasPaginationArgs = hasPaginationArgs;
            this.score = score;
        }

        @Override public String toString() { return field + " : " + returnType; }
    }

    private static final class SchemaModel {
        final Map<String, TypeDef> types = new LinkedHashMap<>();
        String queryTypeName = "Query";

        static SchemaModel tryParse(String sdl) {
            try {
                SchemaModel sm = new SchemaModel();
                String trimmed = sdl == null ? "" : sdl.trim();

                // Support both SDL and Introspection JSON.
                if (looksLikeJson(trimmed)) {
                    sm.parseIntrospectionJson(trimmed);
                    return sm;
                }

                sm.parse(sdl);
                // If SDL parsing produced nothing but the input is JSON, fall back.
                if (sm.types.isEmpty() && looksLikeJson(trimmed)) {
                    sm.parseIntrospectionJson(trimmed);
                }
                return sm;
            } catch (Exception e) {
                return null;
            }
        }

        private static boolean looksLikeJson(String s) {
            if (s == null) return false;
            String t = s.trim();
            return t.startsWith("{") || t.startsWith("[");
        }

        @SuppressWarnings("unchecked")
        private void parseIntrospectionJson(String json) {
            Object rootObj = Json.parse(json);
            if (!(rootObj instanceof Map)) return;
            Map<String, Object> root = (Map<String, Object>) rootObj;

            // Common shapes:
            // 1) { "data": { "__schema": { ... } } }
            // 2) { "__schema": { ... } }
            Object dataObj = root.get("data");
            Map<String, Object> data = (dataObj instanceof Map) ? (Map<String, Object>) dataObj : root;
            Object schemaObj = data.get("__schema");
            if (!(schemaObj instanceof Map)) return;
            Map<String, Object> schema = (Map<String, Object>) schemaObj;

            // Root query type name
            Object qt = schema.get("queryType");
            if (qt instanceof Map) {
                Object qtn = ((Map<?, ?>) qt).get("name");
                if (qtn instanceof String && !((String) qtn).isBlank()) {
                    queryTypeName = (String) qtn;
                }
            }

            Object typesObj = schema.get("types");
            if (!(typesObj instanceof List)) return;
            List<Object> list = (List<Object>) typesObj;

            for (Object tObj : list) {
                if (!(tObj instanceof Map)) continue;
                Map<String, Object> tm = (Map<String, Object>) tObj;
                String kind = asString(tm.get("kind"));
                String name = asString(tm.get("name"));
                if (name == null || name.isBlank()) continue;
                if (name.startsWith("__")) continue;
                if (!"OBJECT".equals(kind)) continue;

                TypeDef td = new TypeDef(name);
                Object fieldsObj = tm.get("fields");
                if (fieldsObj instanceof List) {
                    for (Object fObj : (List<Object>) fieldsObj) {
                        if (!(fObj instanceof Map)) continue;
                        Map<String, Object> fm = (Map<String, Object>) fObj;
                        String fname = asString(fm.get("name"));
                        if (fname == null || fname.isBlank()) continue;

                        String rtype = typeNodeToString(fm.get("type"));
                        List<ArgDef> args = parseArgsFromIntrospection(fm.get("args"));
                        td.fields.add(new FieldDef(fname, rtype, args));
                    }
                }
                types.put(name, td);
            }
        }

        private static String asString(Object o) {
            return (o instanceof String) ? (String) o : null;
        }

        @SuppressWarnings("unchecked")
        private static List<ArgDef> parseArgsFromIntrospection(Object argsObj) {
            if (!(argsObj instanceof List)) return List.of();
            List<ArgDef> out = new ArrayList<>();
            for (Object aObj : (List<Object>) argsObj) {
                if (!(aObj instanceof Map)) continue;
                Map<String, Object> am = (Map<String, Object>) aObj;
                String n = asString(am.get("name"));
                String t = typeNodeToString(am.get("type"));
                if (n == null || t == null) continue;
                out.add(new ArgDef(n, t));
            }
            return out;
        }

        @SuppressWarnings("unchecked")
        private static String typeNodeToString(Object typeNode) {
            if (!(typeNode instanceof Map)) return "";
            Map<String, Object> m = (Map<String, Object>) typeNode;
            String kind = asString(m.get("kind"));
            String name = asString(m.get("name"));
            Object ofType = m.get("ofType");

            if ("NON_NULL".equals(kind)) {
                return typeNodeToString(ofType) + "!";
            }
            if ("LIST".equals(kind)) {
                return "[" + typeNodeToString(ofType) + "]";
            }
            if (name != null) {
                return name;
            }
            // Fallback: sometimes name is null and ofType continues.
            return typeNodeToString(ofType);
        }

        private void parse(String sdl) {
            String cleaned = stripComments(sdl);

            // detect explicit root query type (schema { query: X })
            Matcher qm = Pattern.compile("(?s)\\bschema\\s*\\{.*?\\bquery\\s*:\\s*([_A-Za-z][_0-9A-Za-z]*)", Pattern.CASE_INSENSITIVE).matcher(cleaned);
            if (qm.find()) {
                queryTypeName = qm.group(1);
            }

            // match type blocks
            Matcher tm = Pattern.compile("(?s)\\b(?:type|extend\\s+type)\\s+([_A-Za-z][_0-9A-Za-z]*)\\s*(?:implements\\s+[^\\{]+)?\\s*\\{(.*?)\\}").matcher(cleaned);
            while (tm.find()) {
                String typeName = tm.group(1);
                String body = tm.group(2);
                TypeDef td = new TypeDef(typeName);

                // fields like: field(arg: Type, ...): Return
                Matcher fm = Pattern.compile("(?m)^\\s*([_A-Za-z][_0-9A-Za-z]*)\\s*(\\(([^)]*)\\))?\\s*:\\s*([^\\s@]+)").matcher(body);
                while (fm.find()) {
                    String fname = fm.group(1);
                    String argsRaw = fm.group(3);
                    String rtypeRaw = fm.group(4).trim();
                    FieldDef fd = new FieldDef(fname, rtypeRaw, parseArgs(argsRaw));
                    td.fields.add(fd);
                }

                types.put(typeName, td);
            }
        }

        static String stripComments(String s) {
            return s.replaceAll("(?m)#.*$", "");
        }

        static List<ArgDef> parseArgs(String argsRaw) {
            if (argsRaw == null || argsRaw.isBlank()) return List.of();
            List<ArgDef> out = new ArrayList<>();
            // split by commas not inside brackets (simple)
            String[] parts = argsRaw.split(",");
            for (String p : parts) {
                String pp = p.trim();
                if (pp.isEmpty()) continue;
                int idx = pp.indexOf(':');
                if (idx < 0) continue;
                String n = pp.substring(0, idx).trim();
                String t = pp.substring(idx + 1).trim();
                // remove default values
                int eq = t.indexOf('=');
                if (eq >= 0) t = t.substring(0, eq).trim();
                out.add(new ArgDef(n, t));
            }
            return out;
        }

        List<FieldCandidate> pickHeavyCandidates(int max) {
            List<FieldCandidate> out = new ArrayList<>();
            TypeDef q = types.get(queryTypeName);
            if (q == null) return out;

            for (FieldDef f : q.fields) {
                TypeInfo ti = TypeInfo.from(f.returnType);
                String base = ti.baseType;
                boolean isScalar = SCALARS.contains(base);
                if (isScalar) continue;

                boolean hasPag = f.args.stream().anyMatch(a -> a.isPaginationArg());
                int score = 0;
                if (ti.isList) score += 5;
                if (hasPag) score += 3;
                // heuristic: likely expensive if list or has pagination args
                score += 1;

                out.add(new FieldCandidate(f.name, f.returnType, ti.isList, hasPag, score));
            }

            out.sort((a, b) -> Integer.compare(b.score, a.score));
            if (out.size() > max) return out.subList(0, max);
            return out;
        }

        List<FieldCandidate> pickPaginationFields(int max) {
            List<FieldCandidate> all = pickHeavyCandidates(50);
            List<FieldCandidate> out = new ArrayList<>();
            for (FieldCandidate fc : all) {
                if (fc.hasPaginationArgs) out.add(fc);
            }
            if (out.size() > max) return out.subList(0, max);
            return out;
        }

        String buildHeavyFieldQuery(FieldCandidate fc) {
            if (fc == null) return null;
            TypeInfo ti = TypeInfo.from(fc.returnType);
            if (SCALARS.contains(ti.baseType)) return null;

            // For object/list: { field { __typename } }
            return "query Heavy { " + fc.field + " { __typename } }";
        }

        String buildDepthQuery(int depth) {
            TypeDef q = types.get(queryTypeName);
            if (q == null) return null;

            // Find a path following first object field recursively
            FieldDef start = firstObjectField(q);
            if (start == null) return null;

            StringBuilder sb = new StringBuilder();
            sb.append("query Depth { ");

            String currentType = TypeInfo.from(start.returnType).baseType;
            sb.append(start.name);
            sb.append(" { ");

            int d = 1;
            while (d < depth) {
                TypeDef td = types.get(currentType);
                if (td == null) break;
                FieldDef next = firstObjectField(td);
                if (next == null) break;
                currentType = TypeInfo.from(next.returnType).baseType;
                sb.append(next.name).append(" { ");
                d++;
            }
            sb.append("__typename");
            for (int i = 0; i < d; i++) sb.append(" }");
            sb.append(" }"); // close start selection
            sb.append(" }");

            return sb.toString();
        }

        FieldDef firstObjectField(TypeDef td) {
            for (FieldDef f : td.fields) {
                TypeInfo ti = TypeInfo.from(f.returnType);
                if (!SCALARS.contains(ti.baseType)) {
                    return f;
                }
            }
            return null;
        }

        String buildFragmentExplosionQuery(int spreads) {
            TypeDef q = types.get(queryTypeName);
            if (q == null) return null;
            FieldDef f = firstObjectField(q);
            if (f == null) return null;

            // fragment on Query spreading many times
            String frag = "fragment F on Query { " + f.name + " { __typename } }";
            StringBuilder sb = new StringBuilder();
            sb.append(frag).append("\n");
            sb.append("query FragExplosion {\n");
            for (int i = 0; i < spreads; i++) sb.append("  ...F\n");
            sb.append("}\n");
            return sb.toString();
        }

        String buildPaginationAbuseQuery(FieldCandidate fc, int value) {
            TypeDef q = types.get(queryTypeName);
            if (q == null) return null;
            FieldDef fd = q.findField(fc.field);
            if (fd == null) return null;
            String argName = fd.args.stream().map(a -> a.name).filter(SchemaModel::isPaginationArgName).findFirst().orElse(null);
            if (argName == null) return null;

            TypeInfo ti = TypeInfo.from(fd.returnType);
            if (SCALARS.contains(ti.baseType)) {
                return "query Paginate { " + fd.name + "(" + argName + ":" + value + ") }";
            }
            return "query Paginate { " + fd.name + "(" + argName + ":" + value + ") { __typename } }";
        }

        static boolean isPaginationArgName(String n) {
            if (n == null) return false;
            String x = n.toLowerCase(Locale.ROOT);
            return x.equals("first") || x.equals("last") || x.equals("limit") || x.equals("pagesize") || x.equals("size") || x.equals("take") || x.equals("count");
        }
    }

    private static final class TypeDef {
        final String name;
        final List<FieldDef> fields = new ArrayList<>();

        TypeDef(String name) { this.name = name; }

        FieldDef findField(String fname) {
            for (FieldDef f : fields) if (f.name.equals(fname)) return f;
            return null;
        }
    }

    private static final class FieldDef {
        final String name;
        final String returnType;
        final List<ArgDef> args;

        FieldDef(String name, String returnType, List<ArgDef> args) {
            this.name = name;
            this.returnType = returnType;
            this.args = (args == null) ? List.of() : args;
        }
    }

    private static final class ArgDef {
        final String name;
        final String type;

        ArgDef(String name, String type) { this.name = name; this.type = type; }

        boolean isPaginationArg() { return SchemaModel.isPaginationArgName(name); }
    }

    private static final class TypeInfo {
        final String baseType;
        final boolean isList;

        TypeInfo(String baseType, boolean isList) { this.baseType = baseType; this.isList = isList; }

        static TypeInfo from(String raw) {
            if (raw == null) return new TypeInfo("", false);
            String t = raw.trim();
            boolean list = t.contains("[");
            // remove brackets and non-word
            t = t.replace("[", "").replace("]", "").replace("!", "").trim();
            // base token
            Matcher m = Pattern.compile("([_A-Za-z][_0-9A-Za-z]*)").matcher(t);
            String base = m.find() ? m.group(1) : t;
            return new TypeInfo(base, list);
        }
    }
}
