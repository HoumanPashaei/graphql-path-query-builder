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
    // Sorting toggles
    private boolean sortVulnerableDesc = true;

    private HttpRequestEditor reqEd;
    private HttpResponseEditor resEd;

    // Details panes were removed from the Scanner tab in favor of the Attack Guide.
    // We keep per-row HTML (Row.detailsHtml) for possible future use (e.g., export) but we do not render it in Scanner.
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
    private volatile boolean scanRunning = false;
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
        mainTabs.addTab("Attack Guide", buildGuideTabPanel());

        add(mainTabs, BorderLayout.CENTER);
    }

    // ---------------------------
    // UI: Attack Guide tab
    // ---------------------------

    private static final class GuideScenario {
        final String title;
        final String what;
        final String why;
        final String detection;
        final String mitigations;
        final String notes;
        final String example;

        GuideScenario(String title, String what, String why, String detection, String example, String mitigations, String notes) {
            this.title = title;
            this.what = what;
            this.why = why;
            this.detection = detection;
            this.example = example;
            this.mitigations = mitigations;
            this.notes = notes;
        }
    }

    private JPanel buildGuideTabPanel() {
        List<GuideScenario> scenarios = buildGuideScenarios();

        JPanel root = new JPanel(new BorderLayout(8, 8));
        root.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        JLabel title = new JLabel();
        title.setFont(title.getFont().deriveFont(Font.BOLD, 14f));
        JLabel counter = new JLabel();
        counter.setForeground(Color.DARK_GRAY);

        JPanel header = new JPanel(new BorderLayout());
        header.add(title, BorderLayout.WEST);
        header.add(counter, BorderLayout.EAST);
        root.add(header, BorderLayout.NORTH);

        CardLayout cards = new CardLayout();
        JPanel cardPanel = new JPanel(cards);

        // We keep references so we can update scroll positions on page change.
        List<JEditorPane> htmlPanes = new ArrayList<>();
        List<JTextArea> codeAreas = new ArrayList<>();

        for (int i = 0; i < scenarios.size(); i++) {
            GuideScenario s = scenarios.get(i);

            JEditorPane body = new JEditorPane("text/html", "");
            body.setEditable(false);
            body.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, true);
            body.setText(buildScenarioHtml(s));
            body.setCaretPosition(0);

            JTextArea code = new JTextArea(s.example == null ? "" : s.example);
            code.setEditable(false);
            code.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            code.setLineWrap(true);
            code.setWrapStyleWord(true);
            code.setCaretPosition(0);

            JScrollPane bodyScroll = new JScrollPane(body);
            bodyScroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
            JScrollPane codeScroll = new JScrollPane(code);
            codeScroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);

            JPanel codeWrap = new JPanel(new BorderLayout());
            codeWrap.setBorder(BorderFactory.createTitledBorder("Full Example"));
            codeWrap.add(codeScroll, BorderLayout.CENTER);

            JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, bodyScroll, codeWrap);
            split.setResizeWeight(0.70);

            JPanel page = new JPanel(new BorderLayout());
            page.add(split, BorderLayout.CENTER);

            cardPanel.add(page, String.valueOf(i));
            htmlPanes.add(body);
            codeAreas.add(code);
        }

        root.add(cardPanel, BorderLayout.CENTER);

        JButton prev = new JButton("Prev");
        JButton next = new JButton("Next");
        JPanel footer = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        footer.add(prev);
        footer.add(next);
        root.add(footer, BorderLayout.SOUTH);

        final int[] idx = new int[]{0};

        Runnable refresh = () -> {
            int i = idx[0];
            GuideScenario s = scenarios.get(i);
            title.setText(s.title);
            counter.setText((i + 1) + "/" + scenarios.size());
            cards.show(cardPanel, String.valueOf(i));
            prev.setEnabled(i > 0);
            next.setEnabled(i < scenarios.size() - 1);
            // reset scroll positions
            SwingUtilities.invokeLater(() -> {
                try { htmlPanes.get(i).setCaretPosition(0); } catch (Exception ignored) {}
                try { codeAreas.get(i).setCaretPosition(0); } catch (Exception ignored) {}
            });
        };

        prev.addActionListener(e -> { if (idx[0] > 0) { idx[0]--; refresh.run(); }});
        next.addActionListener(e -> { if (idx[0] < scenarios.size() - 1) { idx[0]++; refresh.run(); }});

        refresh.run();
        return root;
    }

    private String buildScenarioHtml(GuideScenario s) {
        return """
                <html><body style='font-family:Segoe UI, Arial; font-size:12px; line-height:1.45'>
                <p><b>What is it</b><br/>%s</p>
                <p><b>Why it’s vulnerable</b><br/>%s</p>
                <p><b>Detection in this tool</b><br/>%s</p>
                <p><b>Mitigations</b><br/>%s</p>
                <p><b>Notes / pitfalls</b><br/>%s</p>
                </body></html>
                """.formatted(escBr(s.title), escBr(s.what), escBr(s.why), escBr(s.detection), escBr(s.mitigations), escBr(s.notes));
    }

    private static String escBr(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br/>");
    }

    private List<GuideScenario> buildGuideScenarios() {
        List<GuideScenario> out = new ArrayList<>();

        out.add(new GuideScenario(
                "How to interpret results",
                "This tab documents the scenarios tested by DoS Scanner and how to read the table.",
                "GraphQL DoS often depends on both (1) what the server allows (missing limits) and (2) real impact (latency/timeouts). A fast environment can hide impact.",
                "Table columns: \n• Vulnerable = Yes/Maybe/No (capability)\n• Severity = INFO/LOW/MEDIUM/HIGH (scenario-aware, based on magnitude and impact)\n• Reason explains the decision (accepted threshold, blocked by limit, invalid query, etc.)\n• ΔTime vs Baseline helps compare to normal request latency.",
                "--",
                "Use server-side protections: depth & complexity/cost limits, max aliases/fields/directives/fragments, request size limits, batch limits, rate limiting, disable introspection in prod, persisted queries.",
                "Vulnerable=Maybe typically means the result is inconclusive (invalid query due to missing schema, non-JSON response, ambiguous errors)."));

        out.add(new GuideScenario(
                "Alias Overloading (DoS)",
                "GraphQL aliases allow multiple occurrences of the same field in a single operation by renaming each occurrence.",
                "If the server does not cap alias count/cost, a single request can trigger many resolver executions and expensive backend work.",
                "We generate queries with increasing alias counts and mark Vulnerable=Yes when the server accepts counts at/above the configured threshold without limit errors.",
                "query AliasOverloading {\n  a01: user(id: 1) { id }\n  a02: user(id: 1) { id }\n  a03: user(id: 1) { id }\n  # ... repeat up to 100+ aliases\n}",
                "Enforce query complexity/cost, cap max aliases/selection size, rate limit, cache safe queries, use persisted queries.",
                "If schema is not loaded, the tool falls back to a safe field; for the best signal, load schema so the tool can choose valid fields."));

        out.add(new GuideScenario(
                "Array-based Query Batching (DoS)",
                "Some servers accept a JSON array of GraphQL operations (batching).",
                "Each element is executed independently. Without a batch size/cost cap, a single HTTP request can multiply load dramatically.",
                "We send an array body with N operations. Vulnerable=Yes when the server accepts arrays at/above the threshold.",
                "[\n  {\"query\":\"query { __typename }\"},\n  {\"query\":\"query { __typename }\"}\n  // ... repeated 10+ times\n]",
                "Disable batching in production or enforce strict per-request limits (max operations, max total cost), plus global rate limiting.",
                "Some frameworks return 400 with GraphQL errors; the tool may mark Maybe if acceptance is unclear."));

        out.add(new GuideScenario(
                "Field Duplication (DoS)",
                "Repeating the same field many times inside the same selection set (without aliases).",
                "Large selection sets increase parse/validation/planning cost. Some resolvers may also repeat work if the server does not deduplicate.",
                "We repeat a field N times. Vulnerable=Yes when large counts are accepted without limit errors.",
                "query FieldDuplication {\n  user(id: 1) {\n    id\n    id\n    id\n    # ... repeat\n  }\n}",
                "Apply complexity/cost analysis, cap max selection size, cap max query size, validate/normalize duplicate selections.",
                "Even if resolvers deduplicate, parsing/planning can still be abused at large sizes."));

        out.add(new GuideScenario(
                "Directives Overloading (DoS)",
                "Overusing directives by duplicating them many times (e.g., @skip/@include or custom directives).",
                "Directive parsing/validation and execution logic can be abused to consume CPU.",
                "We attach many directives to the same field. Vulnerable=Yes when high counts are accepted.",
                "query DirectivesOverloading($cond:Boolean!){\n  user(id:1) @skip(if:$cond) @skip(if:$cond) @skip(if:$cond) { id }\n}",
                "Limit directive count, cost analysis, disable unnecessary directives, strict validation.",
                "Some servers normalize directives; others may still spend time parsing repeated directives."));

        out.add(new GuideScenario(
                "Introspection Enabled (Info Leak)",
                "Introspection exposes schema metadata (types/fields).",
                "This is usually information leakage, but it also enables targeted DoS (heavy fields, deep types).",
                "We run a minimal introspection query. Severity=INFO when enabled.",
                "query Introspection { __schema { queryType { name } } }",
                "Disable introspection in production or restrict it to authenticated/admin users; prefer allow-listed/persisted operations.",
                "If introspection is disabled, schema-driven tests may be limited unless the user imports schema manually."));

        out.add(new GuideScenario(
                "Introspection-based Deep ofType Nesting (DoS)",
                "A deeply nested introspection query (often repeating ofType) that traverses type metadata repeatedly.",
                "Without depth/cost limits, introspection queries can become heavy.",
                "We increase nesting depth. Vulnerable=Yes when deep nesting at/above threshold is accepted.",
                "query IntrospectionNesting {\n  __schema {\n    types {\n      fields {\n        type {\n          ofType { ofType { ofType { name } } }\n        }\n      }\n    }\n  }\n}",
                "Disable introspection in production; enforce depth/cost limits; cap recursive metadata traversal.",
                "Some servers always allow introspection but enforce depth/cost. That should result in Vulnerable=No with a limit error."));

        out.add(new GuideScenario(
                "Query Depth / Nested Selection (DoS)",
                "Deeply nested selections (e.g., user→friends→friends→...).",
                "Deep nesting increases resolver fan-out and DB load, and can increase response size.",
                "Schema-driven: we build a nested query using available object relationships. Vulnerable=Yes when deep depth is accepted.",
                "query Deep {\n  user(id:1){\n    friends{\n      friends{\n        friends{ id }\n      }\n    }\n  }\n}",
                "Enforce max query depth, cost analysis, pagination enforcement, and avoid unbounded recursive relationships.",
                "Requires schema to reliably build valid deep paths."));

        out.add(new GuideScenario(
                "Fragment Explosion / Nested Fragments (DoS)",
                "Using many fragments and nested fragment spreads to create a huge expanded query.",
                "Parsing/validation and planning cost can grow rapidly after fragment expansion.",
                "Schema-driven: we generate a query that uses many nested fragments. Vulnerable=Yes when large expansions are accepted.",
                "query FragmentExplosion {\n  user(id:1){ ...F1 }\n}\nfragment F1 on User { id name ...F2 }\nfragment F2 on User { id name ...F3 }\n# ...",
                "Limit fragment count and total expanded size, enforce max query size, cost analysis.",
                "Some servers cache parsed documents; attackers can still vary whitespace/aliases to bypass caches."));

        out.add(new GuideScenario(
                "Argument / Variable Bomb (DoS)",
                "Sending extremely large JSON variables payloads or oversized arguments.",
                "Large request bodies increase JSON parsing, validation, and memory pressure.",
                "We send variables payloads of increasing size. Vulnerable=Maybe/Yes depends on acceptance and configured thresholds.",
                "POST body: {\"query\":\"query($x:String!){echo(x:$x)}\", \"variables\":{\"x\":\"AAAA... (very long)\"}}",
                "Enforce request size limits, variable size limits, timeouts, rate limiting, and WAF limits.",
                "Some targets return generic 413/400. The tool reports Reason + status code; interpret with server logs."));

        out.add(new GuideScenario(
                "List Size / Pagination Abuse (DoS)",
                "Abusing pagination arguments (first/limit/pageSize) with huge values.",
                "Large list fetches cause DB load, memory pressure, and slow responses.",
                "Schema-driven: we detect list fields with pagination arguments and try oversized values. Vulnerable=Yes when large values are accepted.",
                "query PaginationAbuse {\n  users(first:100000){ id }\n}",
                "Enforce max page size, require pagination on lists, cap values server-side, and use cost analysis.",
                "Requires schema to find list fields and their argument names."));

        out.add(new GuideScenario(
                "Heavy Objects / Expensive Fields (DoS)",
                "Some fields/resolvers are inherently expensive (joins, aggregations, search).",
                "Repeating expensive operations (aliases/batching) can DoS even if individual requests succeed.",
                "Schema-driven: we rank candidate heavy fields and let the user select additional fields. We then probe them and look for high ΔTime/timeouts.",
                "query Heavy {\n  expensiveField { id }\n}",
                "Resolver optimization (dataloader), caching, timeouts, rate limiting, cost per field, avoid N+1, and cap fan-out.",
                "Heavy detection is environment-dependent; prefer testing on realistic data volumes."));

        out.add(new GuideScenario(
                "Slow Resolver / Heavy Scalar (DoS)",
                "Some GraphQL fields return scalars (String/Boolean/Int/etc.) but are backed by expensive resolvers (e.g., running OS commands, performing maintenance, generating reports). Even without nested selections, repeatedly calling such a field can exhaust server resources.",
                "Because the resolver work happens server-side. If there are no controls like rate limiting, query cost analysis, or per-field execution limits, an attacker can amplify load by aliasing or batching the same expensive scalar field.",
                "If schema is available, DoS Scanner will list likely expensive scalar fields (heuristic by name + root Query fields). Selecting a candidate runs a baseline call and an amplification call (aliases/batch). Vulnerable becomes Yes/Maybe depending on whether the server accepts the amplification and whether impact thresholds are exceeded.",
                "query HeavyScalarBaseline {\n  systemUpdate\n}\n\n# Amplification with aliases\nquery HeavyScalarAmplify {\n  a1: systemUpdate\n  a2: systemUpdate\n  a3: systemUpdate\n  a4: systemUpdate\n  a5: systemUpdate\n}\n",
                "Mitigate by (1) rate limiting and request throttling, (2) query cost / complexity limiting per operation, (3) per-field execution guards (timeouts/circuit breakers), (4) caching for expensive computations, (5) authz checks and disabling risky maintenance fields in production.",
                "Pitfall: a fast dev environment can hide impact; test on realistic data and hardware. Also note that some servers return HTTP 200 with GraphQL errors—use both HTTP and GraphQL-level signals when validating."));


        out.add(new GuideScenario(
                "Baseline Amplification (DoS)",
                "Repeating the baseline query many times (batching-style amplification).",
                "Even normal queries can DoS when amplified. This helps compare protective controls.",
                "We send a batch containing the baseline query repeated N times. High latency/timeouts indicate amplification risk.",
                "[\n  {\"query\":\"<baseline>\"},\n  {\"query\":\"<baseline>\"}\n  // ...\n]",
                "Disable batching or cap it; use cost analysis and rate limits.",
                "This is an impact-driven check; use the Severity + Reason to interpret."));

        return out;
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
                        if (ex != null) {
                            api.logging().logToError("Introspection fetch failed: " + ex);
                        }
                        if (ex == null && !isNullOrBlank(schemaJson)) {
                            schemaArea.setText(schemaJson);
                            schemaArea.setCaretPosition(0);
                            schemaStatus.setText("Schema loaded from introspection.");
                        } else {
                            if (ex != null) {
                                schemaStatus.setText("Introspection failed (continuing without schema). See Burp error log.");
                            } else {
                                schemaStatus.setText("Introspection schema not available (continuing without schema).");
                            }
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

            // Build JSON body (do not rely on Jackson at runtime)
            String body = buildJsonBody(introspectionQuery, "IntrospectionQuery", Map.of());

            HttpRequest req = updateBodyAndHeaders(baselineReq, body, "application/json");
            HttpRequestResponse rr = api.http().sendRequest(req);
            HttpResponse resp = rr.response();
            if (resp == null) return null;

            String text = resp.bodyToString();
            if (isNullOrBlank(text)) {
                api.logging().logToOutput("Introspection returned empty body. HTTP=" + resp.statusCode());
                return null;
            }

            if (resp.statusCode() != 200 || !(text.contains("\"__schema\"") || text.contains("__schema"))) {
                api.logging().logToOutput("Introspection response did not contain __schema. HTTP=" + resp.statusCode());
                return null;
            }
            if (isNullOrBlank(text)) return null;

            return text;
        } catch (Exception e) {
            api.logging().logToError("Introspection fetch exception: " + e);
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
            schemaStatus.setText("Loading Schema File... Please Wait.");
            java.nio.file.Path p = fc.getSelectedFile().toPath();
            String content = java.nio.file.Files.readString(p, java.nio.charset.StandardCharsets.UTF_8);
            schemaArea.setText(content);
            // parse will be triggered by document listener
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Failed to Read Schema File: " + ex.getMessage(), "Schema import", JOptionPane.ERROR_MESSAGE);
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
            schemaStatus.setText("Schema Cleared.");
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
                    85,   // Vulnerable
                    90,   // Severity
                    260,  // Reason
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

    private void sortAllRowsByVulnerable(boolean yesFirst) {
        allRows.sort((a, b) -> {
            int sa = a.vulnerable == null ? 0 : a.vulnerable.score();
            int sb = b.vulnerable == null ? 0 : b.vulnerable.score();
            int cmp = Integer.compare(sa, sb);
            if (yesFirst) cmp = -cmp; // desc
            if (cmp != 0) return cmp;
            // tie-breaker: higher severity then newest
            int scmp = Integer.compare(b.severityScore(), a.severityScore());
            if (scmp != 0) return scmp;
            return Integer.compare(b.index, a.index);
        });
    }

    private void sortAllRowsBySeverity(boolean severityHighFirst) {
        allRows.sort((a, b) -> {
            int sa = a.severityScore();
            int sb = b.severityScore();
            int cmp = Integer.compare(sa, sb);
            if (severityHighFirst) cmp = -cmp;
            if (cmp != 0) return cmp;
            // If same severity, prefer Vulnerable=Yes > Maybe > No.
            int vcmp = Integer.compare(a.vulnerable == null ? 0 : a.vulnerable.score(), b.vulnerable == null ? 0 : b.vulnerable.score());
            vcmp = -vcmp;
            if (vcmp != 0) return vcmp;
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
                if (col == 1) { // Vulnerable
                    sortVulnerableDesc = !sortVulnerableDesc;
                    sortAllRowsByVulnerable(sortVulnerableDesc);
                    currentPage = 1;
                    refreshPage();
                } else if (col == 2) { // Severity
                    // Reuse the same toggle for severity ordering.
                    sortVulnerableDesc = !sortVulnerableDesc;
                    sortAllRowsBySeverity(sortVulnerableDesc);
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

        // Request/Response bottom
        Component reqUi = (reqEd == null) ? new JScrollPane(new JTextArea("Request viewer unavailable.")) : reqEd.uiComponent();
        Component resUi = (resEd == null) ? new JScrollPane(new JTextArea("Response viewer unavailable.")) : resEd.uiComponent();
        JPanel rr = new JPanel(new GridLayout(1, 2, 8, 0));
        rr.add(wrapTitled(reqUi, "Request"));
        rr.add(wrapTitled(resUi, "Response"));

        // Scanner now focuses on results table + request/response. Explanations/examples are in the "Attack Guide" tab.
        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableWrap, rr);
        mainSplit.setResizeWeight(0.55);
        rr.setMinimumSize(new Dimension(200, 260));
        tableWrap.setMinimumSize(new Dimension(200, 220));
        SwingUtilities.invokeLater(() -> {
            try {
                int h = mainSplit.getHeight();
                if (h > 0) mainSplit.setDividerLocation((int)(h * 0.55));
            } catch (Exception ignored) {}
        });

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

        scanRunning = true;
        pool = Executors.newFixedThreadPool(opt.concurrency);

        CompletableFuture
                .supplyAsync(this::sendBaseline, pool)
                .thenRunAsync(this::runAllProbes, pool)
                .whenCompleteAsync((v, ex) -> SwingUtilities.invokeLater(() -> {
                    scanRunning = false;
                    btnStart.setEnabled(true);
                    btnStop.setEnabled(false);
                    shutdownPool();

                    if (ex != null) {
                        String msg = ex.getMessage();
                        if (msg == null) msg = ex.toString();
                        finishedLabel.setText("Status: Finished (error) — " + msg);
                        api.logging().logToError("DoS scan failed: " + ex);

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
        String baseQuery = pg.query;
        if (isNullOrBlank(baseQuery)) {
            // Some targets send raw GraphQL or non-JSON bodies; fall back to a minimal selection.
            baseQuery = "{ __typename }";
        }

        // Prefer schema-derived root field if schema is available. This prevents invalid probes when the
        // imported request is introspection or uses a field that doesn't exist on the target.
        String firstField = null;
        if (schemaModel != null) {
            firstField = schemaModel.pickDefaultQueryFieldName();
        }
        if (isNullOrBlank(firstField)) {
            firstField = guessFirstField(baseQuery);
        }
        if (isNullOrBlank(firstField)) firstField = "__typename";

        // Alias overloading (variants)
        if (opt.testAliasOverloading) {
            for (int n : iterRange(opt.aliasMin, opt.aliasMax, opt.aliasStep)) {
                if (stopRequested.get()) break;
                String q = buildAliasOverloadingQuery(firstField, n);
                sendProbe("Alias Overloading (" + n + ")", q, pg.variables,
                        buildDetailsAndExample(
                                detailsAlias(firstField, n),
                                exampleAlias(firstField, n)
                        ), TestKind.ALIAS, n);
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
                        ), TestKind.FIELD_DUP, n);
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
                        ), TestKind.DIRECTIVES, n);
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
                        buildDetailsAndExample(detailsIntrospection(d), exampleIntrospection(d)),
                        TestKind.INTROSPECTION_NEST, d);
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
                            buildDetailsAndExample(detailsDepth(d), exampleDepth(q)),
                            TestKind.DEPTH, d);
                }
            }

            // Fragment explosion / nested fragments
            if (opt.testFragmentExplosion) {
                for (int n : iterRange(opt.fragMin, opt.fragMax, opt.fragStep)) {
                    if (stopRequested.get()) break;
                    String q = sm.buildFragmentExplosionQuery(n);
                    if (q == null) continue;
                    sendProbe("Fragment Explosion (" + n + ")", q, Map.of(),
                            buildDetailsAndExample(detailsFragments(n), exampleFragments(q)),
                            TestKind.FRAGMENT_EXPLOSION, n);
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
                            buildDetailsAndExample(detailsPagination(fc.field, opt.paginationValue), examplePagination(q)),
                            TestKind.PAGINATION_ABUSE, opt.paginationValue);
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
            // Many servers validate that operationName must exist inside the query document.
            // To keep batching widely compatible, omit operationName entirely.
            arr.add(Map.of(
                    "query", query,
                    "variables", Map.of()
            ));
        }
        String body = toJson(arr);
        HttpRequest req = updateBodyAndHeaders(baselineRequest, body, "application/json");

        sendAndRecord("Heavy Objects (" + fc.field + ", batch=" + batch + ")", req,
                buildDetailsAndExample(
                        detailsHeavy(fc.field, batch),
                        exampleHeavy(query)
                ), TestKind.HEAVY_OBJECT, batch);
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
                buildDetailsAndExample(detailsVariableBomb(bytes), exampleVariableBomb(q, vars)),
                TestKind.VARIABLE_BOMB, bytes);
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

    private void sendProbe(String testName, String query, Map<String, Object> variables, String detailsHtml, TestKind kind, int magnitude) {
        if (stopRequested.get()) return;
        String body = buildJsonBody(query, null, variables);
        HttpRequest req = updateBodyAndHeaders(baselineRequest, body, "application/json");
        sendAndRecord(testName, req, detailsHtml, kind, magnitude);
    }

    private void sendProbe(String testName, String query, Map<String, Object> variables, String detailsHtml) {
        sendProbe(testName, query, variables, detailsHtml, TestKind.OTHER, 0);
    }

    private void sendBatchProbe(String testName, ParsedGraphql pg, int batchSize, String detailsHtml) {
        if (stopRequested.get()) return;

        String q = (pg.query == null || pg.query.isBlank()) ? "query { __typename }" : pg.query;
        Map<String, Object> vars = (pg.variables == null) ? Map.of() : pg.variables;

        List<Map<String, Object>> arr = new ArrayList<>();
        for (int i = 0; i < batchSize; i++) {
            arr.add(Map.of(
                    "query", q,
                    "variables", vars
            ));
        }
        String body = toJson(arr);
        HttpRequest req = updateBodyAndHeaders(baselineRequest, body, "application/json");
        sendAndRecord(testName, req, detailsHtml, TestKind.BATCH, batchSize);
    }

    private void sendBaselineAmplification(ParsedGraphql pg, int batchSize) {
        if (stopRequested.get()) return;
        String q = (pg.query == null || pg.query.isBlank()) ? "query { __typename }" : pg.query;
        Map<String, Object> vars = (pg.variables == null) ? Map.of() : pg.variables;

        List<Map<String, Object>> arr = new ArrayList<>();
        for (int i = 0; i < batchSize; i++) {
            arr.add(Map.of(
                    "query", q,
                    "variables", vars
            ));
        }
        String body = toJson(arr);
        HttpRequest req = updateBodyAndHeaders(baselineRequest, body, "application/json");

        sendAndRecord("Baseline Amplification (batch=" + batchSize + ")", req,
                buildDetailsAndExample(detailsAmplification(batchSize), exampleAmplification(q, batchSize)),
                TestKind.BASELINE_AMP, batchSize);
    }

    private void sendAndRecord(String testName, HttpRequest req, String detailsHtml) {
        sendAndRecord(testName, req, detailsHtml, TestKind.OTHER, 0);
    }

    private void sendAndRecord(String testName, HttpRequest req, String detailsHtml, TestKind kind, int magnitude) {
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
            if (rr != null) resp = rr.response();
        } catch (Exception ex) {
            err = ex.getClass().getSimpleName() + ": " + ex.getMessage();
        }

        int len = (resp == null) ? 0 : resp.body().length();
        int payload = payloadSize(req);
        long delta = (baselineTimeMs > 0) ? (ms - baselineTimeMs) : 0;

        Impact impact = computeImpact(timeout, ms, delta, payload);
        VulnResult vr = evaluateVulnerability(kind, magnitude, resp, timeout, err);

        Row row = Row.from(nextIndex(), testName, req, resp, ms, len, payload, err, timeout, detailsHtml);
        row.deltaTimeMs = delta;
        row.vulnerable = vr.status;
        row.reason = vr.reason;
        row.severity = computeSeverity(kind, row.vulnerable, vr.observedMagnitude, impact);
        addRow(row);
    }

    private String computeSeverity(TestKind kind, VulnStatus status, int observedMagnitude, Impact impact) {
        // Severity is scenario-aware and uses both capability (status/magnitude) and impact (latency/timeout).
        if (status == VulnStatus.NO) {
            // Impact-only: even if capability looks blocked, repeated heavy requests may still cause impact.
            if (impact == Impact.HIGH) return "MEDIUM";
            if (impact == Impact.MEDIUM) return "LOW";
            return "NONE";
        }

        if (kind == TestKind.INTROSPECTION_ENABLED) {
            // Introspection is information leakage, not DoS.
            return status == VulnStatus.YES ? "INFO" : "NONE";
        }

        // If we are unsure, keep severity conservative unless impact is large.
        if (status == VulnStatus.MAYBE) {
            if (impact == Impact.HIGH) return "MEDIUM";
            if (impact == Impact.MEDIUM) return "LOW";
            return "NONE";
        }

        // status == YES
        int t1; // LOW threshold
        int t2; // MEDIUM threshold
        int t3; // HIGH threshold
        switch (kind) {
            case ALIAS -> { t1 = 25; t2 = 50; t3 = opt.vulnAliasThreshold; }
            case BATCH -> { t1 = 4; t2 = 8; t3 = opt.vulnBatchThreshold; }
            case FIELD_DUP -> { t1 = 25; t2 = 50; t3 = opt.vulnFieldDupThreshold; }
            case DIRECTIVES -> { t1 = 25; t2 = 50; t3 = opt.vulnDirectiveThreshold; }
            case INTROSPECTION_NEST -> { t1 = 8; t2 = 12; t3 = opt.vulnIntrospectionDepthThreshold; }
            case DEPTH -> { t1 = 6; t2 = 10; t3 = opt.vulnDepthThreshold; }
            case FRAGMENT_EXPLOSION -> { t1 = 25; t2 = 50; t3 = opt.vulnFragmentThreshold; }
            case VARIABLE_BOMB -> { t1 = 8_000; t2 = 16_000; t3 = opt.vulnVariableBytesThreshold; }
            case PAGINATION_ABUSE -> { t1 = 1000; t2 = 5000; t3 = opt.vulnPaginationThreshold; }
            case HEAVY_OBJECT, BASELINE_AMP -> { t1 = 5; t2 = 10; t3 = 20; }
            default -> { t1 = 1; t2 = 1; t3 = 1; }
        }

        String sev;
        if (observedMagnitude >= t3) sev = "HIGH";
        else if (observedMagnitude >= t2) sev = "MEDIUM";
        else if (observedMagnitude >= t1) sev = "LOW";
        else sev = "LOW";

        // Boost one level if the environment shows clear impact.
        if (impact == Impact.HIGH && !"HIGH".equals(sev)) sev = "HIGH";
        else if (impact == Impact.MEDIUM && "LOW".equals(sev)) sev = "MEDIUM";

        return sev;
    }

    private enum TestKind {
        OTHER,
        ALIAS,
        BATCH,
        FIELD_DUP,
        DIRECTIVES,
        INTROSPECTION_ENABLED,
        INTROSPECTION_NEST,
        DEPTH,
        FRAGMENT_EXPLOSION,
        VARIABLE_BOMB,
        PAGINATION_ABUSE,
        HEAVY_OBJECT,
        BASELINE_AMP
    }

    private static final class VulnResult {
        final VulnStatus status;
        final String reason;
        final int observedMagnitude;

        VulnResult(VulnStatus status, String reason, int observedMagnitude) {
            this.status = (status == null) ? VulnStatus.MAYBE : status;
            this.reason = reason == null ? "" : reason;
            this.observedMagnitude = Math.max(0, observedMagnitude);
        }
    }

    private static final class Impact {
        final String label;
        Impact(String label) { this.label = label; }
        static final Impact NONE = new Impact("None");
        static final Impact LOW = new Impact("Low");
        static final Impact MEDIUM = new Impact("Medium");
        static final Impact HIGH = new Impact("High");
    }

    private Impact computeImpact(boolean timeout, long ms, long delta, int payloadSize) {
        if (timeout) return Impact.HIGH;
        if (baselineTimeMs <= 0) return Impact.NONE;

        // High
        if (ms >= (long) (baselineTimeMs * opt.impactHighMultiplier) || delta >= opt.impactHighAbsoluteIncreaseMs) return Impact.HIGH;
        // Medium
        if (ms >= (long) (baselineTimeMs * opt.impactMediumMultiplier) || delta >= opt.impactMediumAbsoluteIncreaseMs) return Impact.MEDIUM;
        // Low
        if (ms >= (long) (baselineTimeMs * opt.impactLowMultiplier) || delta >= opt.impactLowAbsoluteIncreaseMs) return Impact.LOW;

        // Very large payload can be a weak signal even if time does not spike.
        if (payloadSize >= opt.impactLargePayloadBytes) return Impact.LOW;
        return Impact.NONE;
    }

    private VulnResult evaluateVulnerability(TestKind kind, int magnitude, HttpResponse resp, boolean timeout, String error) {
        if (timeout) {
            // Timeout is a strong impact signal but can still be inconclusive (network / proxy).
            return new VulnResult(VulnStatus.MAYBE, "Timed out while processing payload", magnitude);
        }
        if (resp == null) {
            return new VulnResult(VulnStatus.MAYBE, (error == null || error.isBlank()) ? "No response" : ("Request failed: " + error), magnitude);
        }

        String body = "";
        try { body = resp.bodyToString(); } catch (Exception ignored) {}
        String trimmed = body == null ? "" : body.trim();

        // Introspection enabled is a capability check (Info Leak) used to power schema-driven tests.
        if (kind == TestKind.INTROSPECTION_ENABLED) {
            boolean ok = trimmed.contains("__schema") || trimmed.contains("__type");
            return new VulnResult(ok ? VulnStatus.YES : VulnStatus.NO,
                    ok ? "Introspection returned schema metadata" : "Introspection not available",
                    magnitude);
        }

        // Batch queries: response should be a JSON array when sending an array body.
        if (kind == TestKind.BATCH) {
            boolean accepted = trimmed.startsWith("[") && trimmed.endsWith("]");
            String reason = accepted ? ("Batch array accepted (" + magnitude + " ops)") : "Batch array rejected";
            if (!accepted) {
                return new VulnResult(VulnStatus.NO, reason, magnitude);
            }
            VulnStatus st = magnitude >= opt.vulnBatchThreshold ? VulnStatus.YES : VulnStatus.MAYBE;
            if (st == VulnStatus.MAYBE) reason += " (below threshold)";
            return new VulnResult(st, reason, magnitude);
        }

        // For other probes, parse GraphQL errors (if any).
        boolean hasErrors = false;
        String firstErrorMessage = "";
        try {
            Object parsed = Json.parse(trimmed);
            if (parsed instanceof Map<?,?> map) {
                Object errs = map.get("errors");
                if (errs instanceof List<?> lst && !lst.isEmpty()) {
                    hasErrors = true;
                    Object e0 = lst.get(0);
                    if (e0 instanceof Map<?,?> em) {
                        Object msg = em.get("message");
                        if (msg != null) firstErrorMessage = String.valueOf(msg);
                    }
                }
            }
        } catch (Exception ignored) {
            // If not JSON, fall back to basic string checks.
            hasErrors = trimmed.contains("\"errors\"");
        }

        // If our generated query is invalid (wrong field), the result is inconclusive.
        if (hasErrors) {
            String m = firstErrorMessage == null ? "" : firstErrorMessage;
            String ml = m.toLowerCase(Locale.ROOT);
            if (ml.contains("cannot query field") || ml.contains("unknown argument") || ml.contains("unknown type") || ml.contains("syntax error")) {
                return new VulnResult(VulnStatus.MAYBE,
                        (m.isBlank() ? "GraphQL validation error" : ("GraphQL validation error: " + m)),
                        magnitude);
            }

            // Common limit/defense messages -> treat as blocked.
            if (ml.contains("too complex") || ml.contains("complexity") || ml.contains("depth") || ml.contains("max") || ml.contains("limit") || ml.contains("exceed")) {
                return new VulnResult(VulnStatus.NO,
                        (m.isBlank() ? "Rejected by server limits" : ("Rejected by server limits: " + m)),
                        magnitude);
            }
        }

        boolean accepted = !hasErrors && (resp.statusCode() >= 200 && resp.statusCode() < 300);
        if (!accepted) {
            // Some servers return 400 for GraphQL errors; if we don't have a clear limit signal, keep it MAYBE.
            if (hasErrors) {
                String m = firstErrorMessage == null ? "" : firstErrorMessage;
                return new VulnResult(VulnStatus.MAYBE,
                        m.isBlank() ? "GraphQL errors returned" : ("GraphQL errors returned: " + m),
                        magnitude);
            }
            return new VulnResult(VulnStatus.NO, "Non-2xx response", magnitude);
        }

        int threshold = switch (kind) {
            case ALIAS -> opt.vulnAliasThreshold;
            case FIELD_DUP -> opt.vulnFieldDupThreshold;
            case DIRECTIVES -> opt.vulnDirectiveThreshold;
            case INTROSPECTION_NEST -> opt.vulnIntrospectionDepthThreshold;
            case DEPTH -> opt.vulnDepthThreshold;
            case FRAGMENT_EXPLOSION -> opt.vulnFragmentThreshold;
            case VARIABLE_BOMB -> opt.vulnVariableBytesThreshold;
            case PAGINATION_ABUSE -> opt.vulnPaginationThreshold;
            case HEAVY_OBJECT, BASELINE_AMP, OTHER -> 0;
            default -> 0;
        };
        VulnStatus status;
        if (threshold <= 0) status = VulnStatus.YES;
        else if (magnitude >= threshold) status = VulnStatus.YES;
        else status = VulnStatus.MAYBE;

        String reason;
        switch (kind) {
            case ALIAS -> reason = "Accepted aliases: " + magnitude;
            case FIELD_DUP -> reason = "Accepted duplicate fields: " + magnitude;
            case DIRECTIVES -> reason = "Accepted duplicate directives: " + magnitude;
            case INTROSPECTION_NEST -> reason = "Accepted introspection nesting: " + magnitude;
            case DEPTH -> reason = "Accepted query depth: " + magnitude;
            case FRAGMENT_EXPLOSION -> reason = "Accepted fragment expansion: " + magnitude;
            case VARIABLE_BOMB -> reason = "Accepted variables payload: " + magnitude + " bytes";
            case PAGINATION_ABUSE -> reason = "Accepted pagination size: " + magnitude;
            case HEAVY_OBJECT -> reason = "Accepted heavy object query";
            case BASELINE_AMP -> reason = "Accepted baseline amplification";
            default -> reason = "Accepted";
        }
        if (threshold > 0 && magnitude < threshold) {
            reason += " (below threshold)";
        }
        return new VulnResult(status, reason, magnitude);
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

        // Explanations/examples live in the Attack Guide tab.
    }

    private static String[] splitDetails(String combinedHtml) {
        if (combinedHtml == null) return new String[]{"", ""};
        int marker = combinedHtml.indexOf("<!--EXAMPLE-->");
        if (marker < 0) return new String[]{combinedHtml, ""};
        String a = combinedHtml.substring(0, marker);
        String b = combinedHtml.substring(marker + "<!--EXAMPLE-->".length());
        return new String[]{a, b};
    }

    

    private Integer getSelectedRowStableIndex() {
        try {
            int r = table.getSelectedRow();
            if (r < 0 || r >= viewRows.size()) return null;
            return viewRows.get(r).index;
        } catch (Exception ex) {
            return null;
        }
    }

    private void restoreSelectionByStableIndex(Integer stableIndex) {
        if (stableIndex == null) return;
        for (int i = 0; i < viewRows.size(); i++) {
            if (viewRows.get(i).index == stableIndex) {
                final int rr = i;
                SwingUtilities.invokeLater(() -> {
                    try {
                        table.setRowSelectionInterval(rr, rr);
                        table.scrollRectToVisible(table.getCellRect(rr, 0, true));
                    } catch (Exception ignored) {}
                });
                return;
            }
        }
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
            if (reqEd != null) reqEd.setRequest(HttpRequest.httpRequest(ByteArray.byteArray(new byte[0])));
            if (resEd != null) resEd.setResponse(HttpResponse.httpResponse(ByteArray.byteArray(new byte[0])));
        });
    }

    private void addRow(Row row) {
        synchronized (allRows) {
            allRows.add(row);
        }
        SwingUtilities.invokeLater(() -> {
            Integer sel = getSelectedRowStableIndex();
            refreshPage();
            if (sel != null) {
                restoreSelectionByStableIndex(sel);
            } else if (!scanRunning && table.getSelectedRow() < 0 && !viewRows.isEmpty()) {
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
        Integer sel = getSelectedRowStableIndex();
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
        if (sel != null) restoreSelectionByStableIndex(sel);
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

                // Colorize key columns for faster visual scanning.
                // Column index is based on the view model ordering:
                // 0 Index | 1 Vulnerable | 2 Severity | 3 Reason | ...
                if (!isSelected) {
                    if (column == 1) { // Vulnerable
                        String s = value == null ? "" : String.valueOf(value);
                        if ("Yes".equalsIgnoreCase(s)) c.setForeground(new Color(200, 0, 0));
                        else if ("Maybe".equalsIgnoreCase(s)) c.setForeground(new Color(255, 140, 0));
                        else c.setForeground(Color.DARK_GRAY);
                    } else if (column == 2) { // Severity
                        String s = value == null ? "" : String.valueOf(value);
                        if ("LOW".equalsIgnoreCase(s)) {
                            c.setForeground(new Color(0, 102, 204)); // blue
                        } else if ("MEDIUM".equalsIgnoreCase(s)) {
                            c.setForeground(new Color(255, 140, 0)); // orange
                        } else if ("HIGH".equalsIgnoreCase(s)) {
                            c.setForeground(new Color(200, 0, 0)); // red
                        } else if ("INFO".equalsIgnoreCase(s)) {
                            c.setForeground(new Color(90, 90, 90));
                        } else {
                            c.setForeground(Color.DARK_GRAY);
                        }
                    } else {
                        c.setForeground(Color.DARK_GRAY);
                    }
                }

                if (table.getModel() instanceof DosTableModel m) {
                    Row rr = m.rows.get(row);
                    Font f = c.getFont();
                    boolean bold = rr != null && (rr.vulnerable == VulnStatus.YES || "HIGH".equals(rr.severity) || "MEDIUM".equals(rr.severity));
                    c.setFont(f.deriveFont(bold ? Font.BOLD : Font.PLAIN));
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

        // --- Impact (Potential High/Medium/Low)
        menu.addSeparator();
        menu.add(makeSectionLabel("Impact thresholds"));
        menu.add(makeDoubleSpinnerRow("High: baseline x", opt.impactHighMultiplier, 1.0, 50.0, 0.5, v -> opt.impactHighMultiplier = v));
        menu.add(makeLongSpinnerRow("High: absolute Δms", opt.impactHighAbsoluteIncreaseMs, 0L, 120000L, 250L, v -> opt.impactHighAbsoluteIncreaseMs = v));
        menu.add(makeDoubleSpinnerRow("Medium: baseline x", opt.impactMediumMultiplier, 1.0, 50.0, 0.5, v -> opt.impactMediumMultiplier = v));
        menu.add(makeLongSpinnerRow("Medium: absolute Δms", opt.impactMediumAbsoluteIncreaseMs, 0L, 120000L, 250L, v -> opt.impactMediumAbsoluteIncreaseMs = v));
        menu.add(makeDoubleSpinnerRow("Low: baseline x", opt.impactLowMultiplier, 1.0, 50.0, 0.1, v -> opt.impactLowMultiplier = v));
        menu.add(makeLongSpinnerRow("Low: absolute Δms", opt.impactLowAbsoluteIncreaseMs, 0L, 120000L, 50L, v -> opt.impactLowAbsoluteIncreaseMs = v));
        menu.add(makeIntSpinnerRow("Low: payload bytes", opt.impactLargePayloadBytes, 0, 5_000_000, 1000, v -> opt.impactLargePayloadBytes = v));

        // --- Vulnerability thresholds
        menu.addSeparator();
        menu.add(makeSectionLabel("Vulnerable = Yes if accepted and ≥ threshold"));
        menu.add(makeIntSpinnerRow("Alias threshold", opt.vulnAliasThreshold, 0, 5000, 5, v -> opt.vulnAliasThreshold = v));
        menu.add(makeIntSpinnerRow("Batch threshold", opt.vulnBatchThreshold, 0, 5000, 1, v -> opt.vulnBatchThreshold = v));
        menu.add(makeIntSpinnerRow("Field-dup threshold", opt.vulnFieldDupThreshold, 0, 5000, 5, v -> opt.vulnFieldDupThreshold = v));
        menu.add(makeIntSpinnerRow("Directives threshold", opt.vulnDirectiveThreshold, 0, 5000, 5, v -> opt.vulnDirectiveThreshold = v));
        menu.add(makeIntSpinnerRow("Introspection depth threshold", opt.vulnIntrospectionDepthThreshold, 0, 100, 1, v -> opt.vulnIntrospectionDepthThreshold = v));
        menu.add(makeIntSpinnerRow("Depth threshold", opt.vulnDepthThreshold, 0, 200, 1, v -> opt.vulnDepthThreshold = v));
        menu.add(makeIntSpinnerRow("Fragments threshold", opt.vulnFragmentThreshold, 0, 5000, 5, v -> opt.vulnFragmentThreshold = v));
        menu.add(makeIntSpinnerRow("Variable bytes threshold", opt.vulnVariableBytesThreshold, 0, 50_000_000, 1000, v -> opt.vulnVariableBytesThreshold = v));
        menu.add(makeIntSpinnerRow("Pagination threshold", opt.vulnPaginationThreshold, 0, 1_000_000, 10, v -> opt.vulnPaginationThreshold = v));

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

    // ---------------------------
    // JSON building helpers (no Jackson dependency)
    // ---------------------------
    private static String toJson(Object obj) {
        StringBuilder sb = new StringBuilder(256);
        appendJson(sb, obj);
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static void appendJson(StringBuilder sb, Object obj) {
        if (obj == null) {
            sb.append("null");
            return;
        }
        if (obj instanceof String s) {
            sb.append('"').append(escapeJson(s)).append('"');
            return;
        }
        if (obj instanceof Number || obj instanceof Boolean) {
            sb.append(String.valueOf(obj));
            return;
        }
        if (obj instanceof Map<?, ?> map) {
            sb.append('{');
            boolean first = true;
            for (var e : map.entrySet()) {
                if (!first) sb.append(',');
                first = false;
                sb.append('"').append(escapeJson(String.valueOf(e.getKey()))).append('"').append(':');
                appendJson(sb, e.getValue());
            }
            sb.append('}');
            return;
        }
        if (obj instanceof Iterable<?> it) {
            sb.append('[');
            boolean first = true;
            for (Object v : it) {
                if (!first) sb.append(',');
                first = false;
                appendJson(sb, v);
            }
            sb.append(']');
            return;
        }
        // Fallback: stringify as JSON string
        sb.append('"').append(escapeJson(String.valueOf(obj))).append('"');
    }

    private static String escapeJson(String s) {
        StringBuilder out = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.toString();
    }

    private static String buildJsonBody(String query, String operationName, Map<String, Object> variables) {
        Map<String, Object> m = new LinkedHashMap<>();
        if (operationName != null && !operationName.isBlank()) m.put("operationName", operationName);
        m.put("query", (query == null || query.isBlank()) ? "query { __typename }" : query);
        m.put("variables", (variables == null) ? Map.of() : variables);
        // Do not rely on Jackson presence at runtime; Burp classloaders can conflict.
        return toJson(m);
    }

    private static ParsedGraphql parseGraphqlFromRequest(HttpRequest req) {
        if (req == null) return new ParsedGraphql(null, Map.of());
        try {
            String body = req.bodyToString();
            if (body == null) return new ParsedGraphql(null, Map.of());
            body = body.trim();

            // Raw GraphQL (application/graphql) bodies may start with "query"/"mutation" (or just "{" for shorthand),
            // BUT JSON request bodies also start with "{". Prefer JSON parsing first and only treat as raw GraphQL
            // when it clearly looks like a GraphQL document.
            if (body.startsWith("query") || body.startsWith("mutation") || body.startsWith("subscription")) {
                return new ParsedGraphql(body, Map.of());
            }

            if (body.startsWith("[")) {
                // take first item
                Object parsed = Json.parse(body);
                if (parsed instanceof List<?> lst && !lst.isEmpty() && lst.get(0) instanceof Map<?,?> mm) {
                    String q = String.valueOf(mm.get("query"));
                    Object vars = mm.get("variables");
                    return new ParsedGraphql(q, castVars(vars));
                }
                // Fallback (no JSON parser available): extract first "query" string
                String q = extractJsonStringValue(body, "query");
                if (q != null) return new ParsedGraphql(q, Map.of());
            }

            Object parsed = Json.parse(body);
            if (parsed instanceof Map<?, ?> map) {
                String q = map.get("query") == null ? null : String.valueOf(map.get("query"));
                Object vars = map.get("variables");
                return new ParsedGraphql(q, castVars(vars));
            }
            // Fallback (no JSON parser available)
            String q2 = extractJsonStringValue(body, "query");
            if (q2 != null) return new ParsedGraphql(q2, Map.of());
        } catch (Exception ignored) {
        }
        return new ParsedGraphql(null, Map.of());
    }

    // Very small JSON string extractor for cases where JSON parsing library is unavailable.
    // Extracts the first occurrence of "<key>":"..." and unescapes \n/\r/\t/\\/\".
    private static String extractJsonStringValue(String json, String key) {
        if (json == null || key == null) return null;
        Pattern p = Pattern.compile("\\\"" + Pattern.quote(key) + "\\\"\\s*:\\s*\\\"(.*?)\\\"", Pattern.DOTALL);
        Matcher m = p.matcher(json);
        if (!m.find()) return null;
        return unescapeJsonString(m.group(1));
    }

    private static String unescapeJsonString(String s) {
        if (s == null) return null;
        StringBuilder out = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length()) {
                char n = s.charAt(++i);
                switch (n) {
                    case 'n' -> out.append('\n');
                    case 'r' -> out.append('\r');
                    case 't' -> out.append('\t');
                    case '\\' -> out.append('\\');
                    case '"' -> out.append('"');
                    default -> out.append(n);
                }
            } else {
                out.append(c);
            }
        }
        return out.toString();
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

    private enum VulnStatus {
        NO,
        MAYBE,
        YES;

        String display() {
            return switch (this) {
                case NO -> "No";
                case MAYBE -> "Maybe";
                case YES -> "Yes";
            };
        }

        int score() {
            return switch (this) {
                case YES -> 2;
                case MAYBE -> 1;
                case NO -> 0;
            };
        }

        @Override public String toString() {
            return switch (this) {
                case YES -> "Yes";
                case MAYBE -> "Maybe";
                case NO -> "No";
            };
        }
    }

    private static final class Row {
        final int index;
        VulnStatus vulnerable;
        String severity; // HIGH/MEDIUM/LOW/INFO/NONE
        String reason;
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

            this.vulnerable = VulnStatus.NO;
            this.severity = "NONE";
            this.reason = "";
        }

        int severityScore() {
            if (severity == null) return 0;
            return switch (severity) {
                case "HIGH" -> 4;
                case "MEDIUM" -> 3;
                case "LOW" -> 2;
                case "INFO" -> 1;
                default -> 0;
            };
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
                "Index", "Vulnerable", "Severity", "Reason", "Test", "Status code", "Response Time (ms)", "ΔTime vs Baseline (ms)",
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
                case 1 -> r.vulnerable == null ? "Maybe" : r.vulnerable.display();
                case 2 -> (r.severity == null || r.severity.isBlank()) ? "NONE" : r.severity;
                case 3 -> r.reason;
                case 4 -> r.testName;
                case 5 -> r.statusCode;
                case 6 -> r.responseTimeMs;
                case 7 -> r.deltaTimeMs;
                case 8 -> r.responseLength;
                case 9 -> r.payloadSize;
                case 10 -> r.error;
                case 11 -> r.timeout ? "Yes" : "No";
                default -> "";
            };
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            return switch (columnIndex) {
                case 0 -> Integer.class;
                case 6, 7 -> Long.class;
                case 8, 9 -> Integer.class;
                default -> String.class;
            };
        }
    }

    private static final class Options {
        int timeoutMs = 8000;
        int concurrency = 2;

        // Impact (Potential) thresholds
        // More sensitive defaults (useful in fast local environments like DVGA).
        // Users can tune these from Options.
        double impactHighMultiplier = 1.8;
        long impactHighAbsoluteIncreaseMs = 250;
        double impactMediumMultiplier = 1.3;
        long impactMediumAbsoluteIncreaseMs = 120;
        double impactLowMultiplier = 1.10;
        long impactLowAbsoluteIncreaseMs = 40;
        int impactLargePayloadBytes = 80_000;

        // Vulnerable thresholds ("Yes" if accepted and magnitude >= threshold). Set to 0 to disable.
        int vulnAliasThreshold = 100;
        int vulnBatchThreshold = 10;
        int vulnFieldDupThreshold = 100;
        int vulnDirectiveThreshold = 50;
        int vulnIntrospectionDepthThreshold = 15;
        int vulnDepthThreshold = 12;
        int vulnFragmentThreshold = 80;
        int vulnVariableBytesThreshold = 25000;
        int vulnPaginationThreshold = 10000;

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

                boolean hasPag = f.args.stream().anyMatch(a -> a.isPaginationArg());
                int score = 0;

                if (isScalar) {
                    // Scalar fields can still be expensive (slow resolvers). Include likely-heavy scalars by name.
                    if (!hasPag && looksSlowScalarName(f.name)) {
                        score += 6;
                        out.add(new FieldCandidate(f.name, f.returnType, false, false, score));
                    }
                    continue;
                }

                if (ti.isList) score += 5;
                if (hasPag) score += 3;
                score += 1;

                out.add(new FieldCandidate(f.name, f.returnType, ti.isList, hasPag, score));
            }

            out.sort((a, b) -> Integer.compare(b.score, a.score));
            if (out.size() > max) return out.subList(0, max);
            return out;
        }

        /**
         * Best-effort root field selection used for alias/dup/directives probes.
         * Prefers list-like fields and fields that look like pagination/connection.
         */
        String pickDefaultQueryFieldName() {
            TypeDef q = types.get(queryTypeName);
            if (q == null || q.fields.isEmpty()) return null;

            FieldDef best = null;
            int bestScore = Integer.MIN_VALUE;
            for (FieldDef f : q.fields) {
                if (f == null || f.name == null || f.name.isBlank()) continue;
                TypeInfo ti = TypeInfo.from(f.returnType);
                int score = 0;
                // Prefer non-scalar fields
                if (!SCALARS.contains(ti.baseType)) score += 2;
                // Prefer lists/connections
                if (ti.isList) score += 4;
                if (ti.baseType != null && ti.baseType.toLowerCase(Locale.ROOT).contains("connection")) score += 3;
                // Prefer pagination-like args
                boolean hasPag = f.args.stream().anyMatch(a -> a.isPaginationArg());
                if (hasPag) score += 3;
                // De-prioritize mutations (should not appear on query type, but just in case)
                if (f.name.toLowerCase(Locale.ROOT).startsWith("delete") || f.name.toLowerCase(Locale.ROOT).startsWith("remove")) score -= 2;

                if (score > bestScore) {
                    bestScore = score;
                    best = f;
                }
            }
            return best == null ? null : best.name;
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

            if (SCALARS.contains(ti.baseType)) {
                return "query Heavy { " + fc.field + " }";
            }

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
            // We opened exactly 'd' selection sets (start + nested). Close them all, then close the query.
            for (int i = 0; i < d; i++) sb.append(" }");
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

        static boolean looksSlowScalarName(String n) {
            if (n == null) return false;
            String x = n.toLowerCase(Locale.ROOT);

            return x.contains("system")
                    || x.contains("update")
                    || x.contains("backup")
                    || x.contains("restore")
                    || x.contains("migrate")
                    || x.contains("rebuild")
                    || x.contains("reindex")
                    || x.contains("sync")
                    || x.contains("export")
                    || x.contains("import")
                    || x.contains("report")
                    || x.contains("diagnos")
                    || x.contains("health")
                    || x.contains("status")
                    || x.contains("metrics")
                    || x.contains("maintenance");
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
