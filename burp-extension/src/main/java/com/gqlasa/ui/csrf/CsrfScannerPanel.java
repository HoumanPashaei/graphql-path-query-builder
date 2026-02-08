package com.gqlasa.ui.csrf;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import com.gqlasa.GqlAsaExtension;
import com.gqlasa.util.Json;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.text.*;
import java.awt.*;
import java.awt.event.*;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.awt.Dimension;
import javax.swing.JTextPane;
import javax.swing.text.BadLocationException;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

/**
 * CSRF Scanner tab.
 *
 * Notes:
 * - QueryBuilder tab must remain unchanged; this class is self-contained.
 * - Uses Swing-only viewers; attempts to use Montoya editors if available.
 */
public class CsrfScannerPanel extends JPanel {

    // Singleton instance used by context-menu integrations via reflection.
    private static volatile CsrfScannerPanel INSTANCE;

    private final MontoyaApi api;

    // Current scan options. Updated automatically by the Controls menu.
    private final ScanOptions opt = new ScanOptions();

    // Controls
    private JButton btnStart;
    private JButton btnStop;
    private JButton btnOptions;
    private JButton btnFlags;

    private JPopupMenu optionsMenu;
    private JPopupMenu flagsMenu;

    private JSpinner spMaxVariants;
    private JSpinner spConcurrency;
    private JSpinner spTimeoutMs;
    private JSpinner spRetries;

    private JCheckBoxMenuItem miAllowGraphqlErrors;
    private JCheckBoxMenuItem miCompareDataOnly;
    private JCheckBoxMenuItem miIncludeExtensions;
    private JCheckBoxMenuItem miTestHeaders;
    private JCheckBoxMenuItem miFuzzContentType;

    // Layout components
    private JTable table;
    private JScrollPane tableScrollPane;
    private JPanel pagerPanel;
    private JLabel lblPager;
    private JButton btnPrev;
    private JButton btnNext;

    private JSplitPane mainSplit;
    // request/response viewers container (holds client properties for Montoya editors)

    // Montoya editor UI components are exposed as AWT Components
    private Component requestViewer;
    private Component responseViewer;
    private JComponent viewersContainer;

    private final JLabel statusLabel = new JLabel(" ");

    // Keep a copy of all generated rows so we can render rich explanations
    private final java.util.List<Row> allRows = new ArrayList<>();

    private JScrollPane requestAreaScroll;
    private JScrollPane responseAreaScroll;
    private JTextPane requestPane;
    private JTextPane responsePane;

    private JEditorPane explainPane;
    private JScrollPane explainScroll;

    // Data
    private final CsrfTableModel model;
    private final TableRowSorter<CsrfTableModel> sorter;

    private volatile HttpRequestResponse baseline;
    private volatile HttpRequest baselineRequest;
    private volatile HttpResponse baselineResponse;

    private final AtomicBoolean stopRequested = new AtomicBoolean(false);
    private volatile ExecutorService currentPool;

    // Pagination
    private static final int PAGE_SIZE = 10;
    private int pageIndex = 0;

    public CsrfScannerPanel() {
        this.api = GqlAsaExtension.API;
        INSTANCE = this;
        this.model = new CsrfTableModel();
        this.sorter = new TableRowSorter<>(model);

        setLayout(new BorderLayout());
        setBorder(new EmptyBorder(6, 6, 6, 6));

        add(buildControlsBar(), BorderLayout.NORTH);
        add(buildContent(), BorderLayout.CENTER);

        applyDefaultBaseline();
        refreshPager();
    }

    /**
     * Singleton accessor used by integrations (e.g., context-menu "Send to CSRF Scanner") via reflection.
     */
    public static CsrfScannerPanel getInstance() {
        return INSTANCE;
    }

    // ------------------------- Public API -------------------------

    /**
     * Called by the context menu "Send to CSRF Scanner".
     */
    public void importFromHttpRequestResponse(HttpRequestResponse rr) {
        if (rr == null) return;
        this.baseline = rr;
        this.baselineRequest = rr.request();
        this.baselineResponse = rr.response();

        SwingUtilities.invokeLater(() -> {
            // When a request is sent from Repeater/History/... we auto-start a new scan.
            stopScan();
            startScan();
        });
    }

    // ------------------------- UI -------------------------

    private JComponent buildControlsBar() {
        JPanel bar = new JPanel(new BorderLayout());
        bar.setBorder(new EmptyBorder(0, 0, 6, 0));

        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        JLabel title = new JLabel("CSRF Scanner");
        title.setFont(title.getFont().deriveFont(Font.BOLD, title.getFont().getSize() + 1f));
        left.add(title);
        bar.add(left, BorderLayout.WEST);

        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));

        btnStart = new JButton("Start Scan");
        btnStop = new JButton("Stop");
        btnStop.setEnabled(false);

        // Options (numbers)
        spMaxVariants = new JSpinner(new SpinnerNumberModel(0, 0, 500, 1)); // 0 => all
        spConcurrency = new JSpinner(new SpinnerNumberModel(5, 1, 50, 1));
        spTimeoutMs = new JSpinner(new SpinnerNumberModel(10000, 1000, 120000, 500));
        spRetries = new JSpinner(new SpinnerNumberModel(1, 0, 10, 1));

        // Flags (booleans)
        miAllowGraphqlErrors = new JCheckBoxMenuItem("Allow GraphQL errors", true);
        miCompareDataOnly = new JCheckBoxMenuItem("Compare data-only", true);
        miIncludeExtensions = new JCheckBoxMenuItem("Include extensions", false);
        miTestHeaders = new JCheckBoxMenuItem("Test headers", true);
        miFuzzContentType = new JCheckBoxMenuItem("Fuzz content-type", true);

        optionsMenu = buildOptionsMenu();
        flagsMenu = buildFlagsMenu();

        btnOptions = new JButton("Options \u25BE");
        btnFlags = new JButton("Flags \u25BE");
        btnOptions.addActionListener(e -> optionsMenu.show(btnOptions, 0, btnOptions.getHeight()));
        btnFlags.addActionListener(e -> flagsMenu.show(btnFlags, 0, btnFlags.getHeight()));

        right.add(btnStart);
        right.add(btnStop);
        right.add(btnOptions);
        right.add(btnFlags);
        bar.add(right, BorderLayout.EAST);

        // Auto-apply (no separate Save)
        ChangeListener onSpin = new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent e) {
                opt.maxVariants = ((Number) spMaxVariants.getValue()).intValue();
                opt.concurrency = ((Number) spConcurrency.getValue()).intValue();
                opt.timeoutMs = ((Number) spTimeoutMs.getValue()).intValue();
                opt.retries = ((Number) spRetries.getValue()).intValue();
            }
        };
        spMaxVariants.addChangeListener(onSpin);
        spConcurrency.addChangeListener(onSpin);
        spTimeoutMs.addChangeListener(onSpin);
        spRetries.addChangeListener(onSpin);
        onSpin.stateChanged(null);

        ActionListener onFlag = (ActionEvent e) -> {
            opt.allowGraphqlErrors = miAllowGraphqlErrors.isSelected();
            opt.compareDataOnly = miCompareDataOnly.isSelected();
            opt.includeExtensions = miIncludeExtensions.isSelected();
            opt.testHeaders = miTestHeaders.isSelected();
            opt.fuzzContentType = miFuzzContentType.isSelected();
        };
        miAllowGraphqlErrors.addActionListener(onFlag);
        miCompareDataOnly.addActionListener(onFlag);
        miIncludeExtensions.addActionListener(onFlag);
        miTestHeaders.addActionListener(onFlag);
        miFuzzContentType.addActionListener(onFlag);
        onFlag.actionPerformed(null);

        statusLabel.setBorder(new EmptyBorder(4, 8, 0, 8));
        statusLabel.setFont(statusLabel.getFont().deriveFont(statusLabel.getFont().getSize2D() - 1f));
        bar.add(statusLabel, BorderLayout.SOUTH);

        btnStart.addActionListener(e -> startScan());
        btnStop.addActionListener(e -> stopRequested.set(true));

        return bar;
    }

    private JPopupMenu buildOptionsMenu() {
        JPopupMenu m = new JPopupMenu();
        m.setBorder(new EmptyBorder(6, 6, 6, 6));
        m.setLayout(new BoxLayout(m, BoxLayout.Y_AXIS));
        m.add(menuRow("Max variants (0 = all)", spMaxVariants));
        m.add(menuRow("Concurrency", spConcurrency));
        m.add(menuRow("Timeout (ms)", spTimeoutMs));
        m.add(menuRow("Retries", spRetries));
        return m;
    }

    private JPopupMenu buildFlagsMenu() {
        JPopupMenu m = new JPopupMenu();
        m.add(miAllowGraphqlErrors);
        m.add(miCompareDataOnly);
        m.add(miIncludeExtensions);
        m.add(miTestHeaders);
        m.add(miFuzzContentType);
        return m;
    }

    private static JComponent menuRow(String label, JComponent comp) {
        // Use a plain panel (not JMenuItem) so controls remain interactive.
        JPanel p = new JPanel(new BorderLayout(8, 0));
        p.setBorder(new EmptyBorder(4, 8, 4, 8));
        p.setOpaque(false);
        JLabel l = new JLabel(label);
        l.setFont(l.getFont().deriveFont(l.getFont().getSize2D() - 1f));
        p.add(l, BorderLayout.WEST);

        comp.setFocusable(true);
        p.add(comp, BorderLayout.EAST);
        return p;
    }

    private static JPanel labeled(String label, JComponent comp) {
        JPanel p = new JPanel(new BorderLayout(4, 0));
        JLabel l = new JLabel(label);
        l.setFont(l.getFont().deriveFont(l.getFont().getSize2D() - 1f));
        p.add(l, BorderLayout.WEST);
        p.add(comp, BorderLayout.CENTER);
        return p;
    }

    private JComponent buildContent() {
        // Left: table + pager
        table = new JTable(model);
        table.setRowSorter(sorter);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setRowHeight(24);
        table.setIntercellSpacing(new Dimension(10, 4));
        table.setFillsViewportHeight(true);

        // Column sizing
        if (table.getColumnCount() >= 7) {
            table.getColumnModel().getColumn(0).setPreferredWidth(260);
            table.getColumnModel().getColumn(1).setPreferredWidth(80);
            table.getColumnModel().getColumn(2).setPreferredWidth(80);
            table.getColumnModel().getColumn(3).setPreferredWidth(90);
            table.getColumnModel().getColumn(4).setPreferredWidth(120);
            table.getColumnModel().getColumn(5).setPreferredWidth(260);
        }

        // Bold rows with Potential=Yes
        DefaultTableCellRenderer boldYes = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable tbl, Object val, boolean sel, boolean focus, int row, int col) {
                Component c = super.getTableCellRendererComponent(tbl, val, sel, focus, row, col);
                int modelRow = tbl.convertRowIndexToModel(row);
                boolean yes = model.isPotentialYes(modelRow);
                c.setFont(c.getFont().deriveFont(yes ? Font.BOLD : Font.PLAIN));
                return c;
            }
        };
        for (int i = 0; i < table.getColumnCount(); i++) {
            table.getColumnModel().getColumn(i).setCellRenderer(boldYes);
        }

        // Sort Potential=Yes first
        sorter.setComparator(4, (a, b) -> {
            String sa = String.valueOf(a);
            String sb = String.valueOf(b);
            boolean ya = "Yes".equalsIgnoreCase(sa);
            boolean yb = "Yes".equalsIgnoreCase(sb);
            if (ya == yb) return sa.compareToIgnoreCase(sb);
            return ya ? -1 : 1;
        });

        table.getSelectionModel().addListSelectionListener(this::onRowSelected);
        installTablePopup();

        tableScrollPane = new JScrollPane(table);

        pagerPanel = buildPager();

        JPanel left = new JPanel(new BorderLayout(0, 6));
        left.add(tableScrollPane, BorderLayout.CENTER);
        left.add(pagerPanel, BorderLayout.SOUTH);

        // Explain panel (top-right)
        explainPane = new JEditorPane("text/html", "");
        explainPane.setEditable(false);
        explainScroll = new JScrollPane(explainPane);

        // Viewer uses Montoya editors if available, otherwise styled text panes.
        viewersContainer = buildRequestResponseViewers();

        // Top row: Table (left) + Explanation (right)
        JSplitPane topSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left, explainScroll);
        topSplit.setResizeWeight(0.55);

        // Bottom row: Request/Response viewers spanning full width
        JSplitPane outer = new JSplitPane(JSplitPane.VERTICAL_SPLIT, topSplit, viewersContainer);
        outer.setResizeWeight(0.60);

        return outer;
    }

    private JPanel buildPager() {
        JPanel p = new JPanel(new BorderLayout());

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        btnPrev = new JButton("Prev");
        btnNext = new JButton("Next");
        lblPager = new JLabel("Page 1/1");

        btnPrev.addActionListener(e -> {
            if (pageIndex > 0) {
                pageIndex--;
                applyPaging();
            }
        });
        btnNext.addActionListener(e -> {
            if (pageIndex < maxPageIndex()) {
                pageIndex++;
                applyPaging();
            }
        });

        buttons.add(btnPrev);
        buttons.add(btnNext);
        buttons.add(lblPager);
        p.add(buttons, BorderLayout.WEST);
        return p;
    }

    private JComponent buildRequestResponseViewers() {
        // Try Montoya editors first (if present in runtime). If unavailable, fall back.
        try {
            HttpRequestEditor reqEd = api.userInterface().createHttpRequestEditor();
            HttpResponseEditor resEd = api.userInterface().createHttpResponseEditor();
            requestViewer = reqEd.uiComponent();
            responseViewer = resEd.uiComponent();

            JPanel container = new JPanel(new GridLayout(1, 2, 8, 0));
            container.add(wrapTitled(requestViewer, "Request"));
            container.add(wrapTitled(responseViewer, "Response"));

            // Store editors in client properties for later updates
            container.putClientProperty("reqEditor", reqEd);
            container.putClientProperty("resEditor", resEd);
            return container;
        } catch (Throwable t) {
            // Fall back to styled panes.
        }

        requestPane = new JTextPane();
        responsePane = new JTextPane();
        setupViewerPane(requestPane);
        setupViewerPane(responsePane);

        requestAreaScroll = new JScrollPane(requestPane);
        responseAreaScroll = new JScrollPane(responsePane);

        // Remove horizontal scroll explicitly.
        requestAreaScroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        responseAreaScroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);

        JPanel container = new JPanel(new GridLayout(1, 2, 8, 0));
        container.add(wrapTitled(requestAreaScroll, "Request"));
        container.add(wrapTitled(responseAreaScroll, "Response"));
        return container;
    }

    private static void setupViewerPane(JTextPane pane) {
        pane.setEditable(false);
        pane.setFont(new Font("Consolas", Font.PLAIN, 12));
        pane.setBorder(new EmptyBorder(6, 6, 6, 6));
    }

    private static JComponent wrapTitled(Component comp, String title) {
        JPanel p = new JPanel(new BorderLayout());
        JLabel l = new JLabel(title);
        l.setBorder(new EmptyBorder(0, 0, 4, 0));
        l.setFont(l.getFont().deriveFont(Font.BOLD));
        p.add(l, BorderLayout.NORTH);
        p.add(comp, BorderLayout.CENTER);
        return p;
    }

    private void onRowSelected(ListSelectionEvent e) {
        if (e.getValueIsAdjusting()) return;
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) return;
        int modelRow = table.convertRowIndexToModel(viewRow);
        Row r = model.getRow(modelRow);
        if (r == null) return;

        setExplainHtml(buildExplainHtml(r));
        showRequestResponse(r);
    }




    private void installTablePopup() {
        final JPopupMenu popup = new JPopupMenu();
        final JMenuItem sendToRepeater = new JMenuItem("Send to Repeater");
        sendToRepeater.addActionListener(e -> {
            Row r = getSelectedModelRow();
            if (r != null && r.request != null) {
                api.repeater().sendToRepeater(r.request);
            }
        });
        popup.add(sendToRepeater);

        table.addMouseListener(new MouseAdapter() {
            private void maybeShow(MouseEvent e) {
                if (!e.isPopupTrigger()) return;
                int viewRow = table.rowAtPoint(e.getPoint());
                if (viewRow >= 0 && viewRow < table.getRowCount()) {
                    table.setRowSelectionInterval(viewRow, viewRow);
                }
                sendToRepeater.setEnabled(getSelectedModelRow() != null);
                popup.show(e.getComponent(), e.getX(), e.getY());
            }

            @Override
            public void mousePressed(MouseEvent e) { maybeShow(e); }

            @Override
            public void mouseReleased(MouseEvent e) { maybeShow(e); }
        });
    }

    private Row getSelectedModelRow() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) return null;
        int modelRow = table.convertRowIndexToModel(viewRow);
        if (modelRow < 0 || modelRow >= model.getRowCount()) return null;
        return model.getRow(modelRow);
    }
    private void showRequestResponse(Row r) {
        if (r == null) return;

        // If we have Montoya editors
        JComponent viewers = findViewersContainer();
        if (viewers != null) {
            Object reqEdObj = viewers.getClientProperty("reqEditor");
            Object resEdObj = viewers.getClientProperty("resEditor");
            if (reqEdObj instanceof HttpRequestEditor reqEd && resEdObj instanceof HttpResponseEditor resEd) {
                reqEd.setRequest(r.request);
                if (r.response != null) resEd.setResponse(r.response);
                else resEd.setResponse(HttpResponse.httpResponse());
                return;
            }
        }

        setHttpStyled(requestPane, r.request != null ? r.request.toString() : "");
        setHttpStyled(responsePane, r.response != null ? r.response.toString() : "");
    }

    private JComponent findViewersContainer() {
        return viewersContainer;
    }

    private void setExplainHtml(String html) {
        explainPane.setText(html);
        explainPane.setCaretPosition(0);
    }

    // Simple HTTP styling: request line / status line, headers bold, body normal.
    private static void setHttpStyled(JTextPane pane, String raw) {
        if (pane == null) return;

        StyledDocument doc = pane.getStyledDocument();
        try {
            doc.remove(0, doc.getLength());

            Style base = doc.addStyle("base", null);
            StyleConstants.setFontFamily(base, pane.getFont().getFamily());
            StyleConstants.setFontSize(base, pane.getFont().getSize());

            Style bold = doc.addStyle("bold", base);
            StyleConstants.setBold(bold, true);

            String[] parts = raw.split("\\r?\\n\\r?\\n", 2);
            String head = parts.length > 0 ? parts[0] : raw;
            String body = parts.length > 1 ? parts[1] : "";

            String[] lines = head.split("\\r?\\n");
            for (int i = 0; i < lines.length; i++) {
                String line = lines[i];
                if (i == 0) {
                    doc.insertString(doc.getLength(), line + "\\n", bold);
                    continue;
                }
                int idx = line.indexOf(':');
                if (idx > 0) {
                    String k = line.substring(0, idx + 1);
                    String v = line.substring(idx + 1);
                    doc.insertString(doc.getLength(), k, bold);
                    doc.insertString(doc.getLength(), v + "\\n", base);
                } else {
                    doc.insertString(doc.getLength(), line + "\\n", base);
                }
            }

            doc.insertString(doc.getLength(), "\\n", base);
            doc.insertString(doc.getLength(), body, base);
            pane.setCaretPosition(0);
        } catch (BadLocationException ignored) {
        }
    }

    // ------------------------- Scan logic -------------------------

    private void applyDefaultBaseline() {
        // Placeholder baseline row when panel is opened without imported request.
        model.clearAll();
        addBaselineRow();
        selectRowIfAny(0);
        setExplainHtml(buildExplainHtml(null));
    }

    private void addBaselineRow() {
        if (baselineRequest == null) {
            showStatus("Select a GraphQL request as baseline before starting the scan.");
            return;
        }

        Row base = new Row();
        base.index = 0;
        base.variant = "Baseline";
        base.request = baselineRequest;
        base.response = baselineResponse;
        base.method = baselineRequest.method();
        base.status = baselineResponse != null ? baselineResponse.statusCode() : 0;
        base.length = safeBody(baselineResponse).length();
        base.potential = "";
        base.notes = "";
        model.addRow(base);
    }

    private void selectRowIfAny(int modelRow) {
        if (model.getRowCount() <= 0) return;
        int viewRow = table.convertRowIndexToView(Math.max(0, Math.min(modelRow, model.getRowCount() - 1)));
        table.getSelectionModel().setSelectionInterval(viewRow, viewRow);
    }

    private void showStatus(String msg) {
        SwingUtilities.invokeLater(() -> {
            statusLabel.setText(msg == null || msg.isBlank() ? " " : msg);
        });
    }

    private void startScan() {
        if (baseline == null || baselineRequest == null) {
            JOptionPane.showMessageDialog(this, "No baseline request. Use context menu: Send to CSRF Scanner.");
            return;
        }

        stopRequested.set(false);
        btnStart.setEnabled(false);
        btnStop.setEnabled(true);

        model.clearAll();
        pageIndex = 0;
        addBaselineRow();

        ScanOptions opt = readOptionsFromUI();

        // Build variants
        List<Variant> variants = buildVariants(baselineRequest, opt);
        if (opt.maxVariants > 0 && variants.size() > opt.maxVariants) {
            variants = variants.subList(0, opt.maxVariants);
        }

        ExecutorService pool = Executors.newFixedThreadPool(opt.concurrency);
        currentPool = pool;

        // baseline comparison data
        String baselineBody = safeBody(baselineResponse);
        Map<String, Object> baselineMap = tryParseJson(baselineBody);

        List<Future<Row>> futures = new ArrayList<>();
        int idx = 1;
        for (Variant v : variants) {
            final int rowIdx = idx++;
            futures.add(pool.submit(() -> runVariant(rowIdx, v, opt, baselineBody, baselineMap)));
        }

        pool.shutdown();

        // Collect asynchronously on a background thread, push results into Swing
        new Thread(() -> {
            try {
                for (Future<Row> f : futures) {
                    if (stopRequested.get()) break;
                    Row r = f.get(5, TimeUnit.MINUTES);
                    SwingUtilities.invokeLater(() -> {
                        model.addRow(r);
                        refreshPager();
                    });
                }
            } catch (Exception ex) {
                api.logging().logToError("CSRF scan failed: " + ex);
            } finally {
                SwingUtilities.invokeLater(() -> {
                    btnStart.setEnabled(true);
                    btnStop.setEnabled(false);
                    stopRequested.set(false);

                    // Default sort: Potential CSRF (Yes first)
                    try {
                        sorter.setSortKeys(java.util.List.of(new javax.swing.RowSorter.SortKey(4, javax.swing.SortOrder.DESCENDING)));
                    } catch (Exception ignore) {
                        // ignore
                    }
                    pageIndex = 0;
                    applyPaging();
                    refreshPager();
                });

                currentPool = null;
            }
        }, "csrf-scan-collector").start();
    }

    private void stopScan() {
        stopRequested.set(true);
        ExecutorService pool = currentPool;
        if (pool != null) {
            try { pool.shutdownNow(); } catch (Exception ignored) {}
        }
        SwingUtilities.invokeLater(() -> {
            btnStart.setEnabled(true);
            btnStop.setEnabled(false);
            showStatus("Stop requested.");
        });
    }

    private ScanOptions readOptionsFromUI() {
        ScanOptions o = new ScanOptions();
        o.maxVariants = (Integer) spMaxVariants.getValue();
        o.concurrency = (Integer) spConcurrency.getValue();
        o.timeoutMs = (Integer) spTimeoutMs.getValue();
        o.retries = (Integer) spRetries.getValue();

        // Boolean options are controlled by the Controls->Flags menu.
        o.allowGraphqlErrors = miAllowGraphqlErrors.isSelected();
        o.compareDataOnly = miCompareDataOnly.isSelected();
        o.includeExtensions = miIncludeExtensions.isSelected();
        o.testHeaders = miTestHeaders.isSelected();
        o.fuzzContentType = miFuzzContentType.isSelected();
        return o;
    }

    private Row runVariant(int index, Variant v, ScanOptions opt, String baselineBody, Map<String, Object> baselineMap) {
        Row r = new Row();
        r.index = index;
        r.variant = v.name;
        r.request = v.request;
        r.method = v.request.method();

        HttpResponse resp = null;
        int attempts = Math.max(1, opt.retries + 1);
        for (int i = 0; i < attempts; i++) {
            if (stopRequested.get()) break;
            try {
                HttpRequestResponse rr = api.http().sendRequest(v.request);
                resp = rr.response();
                break;
            } catch (Exception ex) {
                if (i == attempts - 1) api.logging().logToError("Request failed: " + ex);
                try { Thread.sleep(150L * (i + 1)); } catch (InterruptedException ignored) {}
            }
        }

        r.response = resp;
        r.status = resp != null ? resp.statusCode() : 0;
        String body = safeBody(resp);
        r.length = body.length();

        boolean ok = isSimilar(baselineBody, baselineMap, body, resp, opt);
        r.potential = ok ? "Yes" : "No";
        r.notes = v.note;

        return r;
    }

    private static String safeBody(HttpResponse resp) {
        if (resp == null) return "";
        try {
            ByteArray b = resp.body();
            if (b == null) return "";
            return b.toString();
        } catch (Exception e) {
            return "";
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> tryParseJson(String body) {
        try {
            if (body == null || body.isBlank()) return Map.of();
            String trimmed = body.trim();
            if (!(trimmed.startsWith("{") && trimmed.endsWith("}"))) return Map.of();
            return Json.parseMap(trimmed);
        } catch (Exception e) {
            return Map.of();
        }
    }

    private boolean isSimilar(String baselineBody, Map<String, Object> baselineMap, String variantBody, HttpResponse variantResp, ScanOptions opt) {
        if (variantResp == null) return false;

        // Status code equality is a strong signal.
        int baseStatus = baselineResponse != null ? baselineResponse.statusCode() : 0;
        if (baseStatus != 0 && variantResp.statusCode() != baseStatus) return false;

        Map<String, Object> varMap = tryParseJson(variantBody);

        // GraphQL error handling
        boolean baseHasErrors = hasGraphqlErrors(baselineMap);
        boolean varHasErrors = hasGraphqlErrors(varMap);
        if (!opt.allowGraphqlErrors) {
            if (baseHasErrors || varHasErrors) return false;
        }

        // Compare data only
        if (opt.compareDataOnly) {
            Object baseData = baselineMap.get("data");
            Object varData = varMap.get("data");
            if (!Objects.equals(Json.compact(baseData), Json.compact(varData))) return false;
        }

        // Extensions
        if (opt.includeExtensions) {
            Object be = baselineMap.get("extensions");
            Object ve = varMap.get("extensions");
            if (!Objects.equals(Json.compact(be), Json.compact(ve))) return false;
        }

        // Length heuristic (fallback)
        int bl = baselineBody != null ? baselineBody.length() : 0;
        int vl = variantBody != null ? variantBody.length() : 0;
        if (bl == 0) return vl == 0;
        double ratio = Math.abs(bl - vl) / (double) bl;
        return ratio <= 0.15; // 15% drift
    }

    private static boolean hasGraphqlErrors(Map<String, Object> map) {
        Object errors = map.get("errors");
        if (errors instanceof Collection<?> c) return !c.isEmpty();
        return errors != null;
    }

    // ------------------------- Variant generation -------------------------

    private List<Variant> buildVariants(HttpRequest base, ScanOptions opt) {
        List<Variant> out = new ArrayList<>();

        // Header-based scenarios
        if (opt.testHeaders) {
            // Only add No Authorization if baseline has Authorization
            if (headerValue(base, "Authorization") != null) {
                out.add(new Variant("No Authorization", removeHeader(base, "Authorization"), "Removed Authorization header"));
            }
            // Only add No Cookie if baseline has Cookie
            if (headerValue(base, "Cookie") != null) {
                out.add(new Variant("No Cookie", removeHeader(base, "Cookie"), "Removed Cookie header"));
            }

            out.add(new Variant("No Origin", removeHeader(base, "Origin"), "Removed Origin header"));
            out.add(new Variant("No Referer", removeHeader(base, "Referer"), "Removed Referer header"));
            out.add(new Variant("Origin: null", setOrReplaceHeader(base, "Origin", "null"), "Set Origin to null"));
            out.add(new Variant("Referer: https://evil.example/", setOrReplaceHeader(base, "Referer", "https://evil.example/"), "Set Referer to attacker origin"));
        }

        // Content-Type fuzzing (browser-simple types + common GraphQL variants)
        if (opt.fuzzContentType) {
            String boundary = "----gqlasa" + System.currentTimeMillis();

            // JSON variants
            out.add(new Variant("CT: application/json; charset=utf-8", setOrReplaceHeader(base, "Content-Type", "application/json; charset=utf-8"), "Charset JSON"));
            out.add(new Variant("CT: application/json;charset=UTF-8", setOrReplaceHeader(base, "Content-Type", "application/json;charset=UTF-8"), "Charset JSON"));
            out.add(new Variant("CT: application/vnd.api+json", setOrReplaceHeader(base, "Content-Type", "application/vnd.api+json"), "Vendor JSON"));

            // Simple types (often allowed by browsers in CSRF)
            out.add(new Variant("CT: text/plain", setOrReplaceHeader(base, "Content-Type", "text/plain"), "Simple content-type"));
            out.add(new Variant("CT: text/plain; charset=UTF-8", setOrReplaceHeader(base, "Content-Type", "text/plain; charset=UTF-8"), "Simple content-type"));
            out.add(new Variant("CT: text/plain;charset=utf-8", setOrReplaceHeader(base, "Content-Type", "text/plain;charset=utf-8"), "Simple content-type"));

            // application/graphql: body is query only
            out.add(new Variant("CT: application/graphql", mutateContentTypeAndBody(base, "application/graphql", buildApplicationGraphqlBody(base)), "Body is raw query"));
            out.add(new Variant("CT: application/graphql; charset=utf-8", mutateContentTypeAndBody(base, "application/graphql; charset=utf-8", buildApplicationGraphqlBody(base)), "Body is raw query"));

            // form-urlencoded: query/variables as fields
            out.add(new Variant("CT: application/x-www-form-urlencoded", mutateContentTypeAndBody(base, "application/x-www-form-urlencoded", buildFormUrlencodedBody(base)), "Form-urlencoded body"));
            out.add(new Variant("CT: x-www-form-urlencoded (query only)", mutateContentTypeAndBody(base, "application/x-www-form-urlencoded", buildFormUrlencodedBodyQueryOnly(base)), "Form-urlencoded query-only"));
            out.add(new Variant("CT: x-www-form-urlencoded (graphql=JSON)", mutateContentTypeAndBody(base, "application/x-www-form-urlencoded", buildFormUrlencodedBodyGraphqlJson(base)), "Form-urlencoded graphql field"));
            out.add(new Variant("CT: application/x-www-form-urlencoded; charset=UTF-8",
                    mutateContentTypeAndBody(base, "application/x-www-form-urlencoded; charset=UTF-8", buildFormUrlencodedBody(base)),
                    "Form-urlencoded body"));

            // multipart/form-data
            out.add(new Variant("CT: multipart/form-data", mutateContentTypeAndBody(base, "multipart/form-data; boundary=" + boundary, buildMultipartBody(base, boundary)), "Multipart form body"));
            out.add(new Variant("CT: multipart/form-data; charset=UTF-8", mutateContentTypeAndBody(base, "multipart/form-data; boundary=" + boundary + "; charset=UTF-8", buildMultipartBody(base, boundary)), "Multipart form body"));

            // Missing content-type
            out.add(new Variant("No Content-Type", removeHeader(base, "Content-Type"), "Removed Content-Type"));

            // Weird but seen in wild
            out.add(new Variant("CT: application/json (mixed case)", setOrReplaceHeader(base, "Content-Type", "Application/Json"), "Case variation"));
        }



        // GET variants (GraphQL over GET)
        if (!"GET".equalsIgnoreCase(base.method())) {
            Variant gv1 = buildGetVariant(base, "GET (query param)", false);
            if (gv1 != null) out.add(gv1);
            Variant gv2 = buildGetVariant(base, "GET (query+variables)", true);
            if (gv2 != null) out.add(gv2);
        }

        // Deduplicate by name
        LinkedHashMap<String, Variant> uniq = new LinkedHashMap<>();
        for (Variant v : out) uniq.putIfAbsent(v.name, v);
        return new ArrayList<>(uniq.values());
    }


        private static String headerValue(HttpRequest req, String name) {
            if (req == null || name == null) {
                return null;
            }
            try {
                for (HttpHeader h : req.headers()) {
                    if (h != null && h.name() != null && h.name().equalsIgnoreCase(name)) {
                        return h.value();
                    }
                }
            } catch (Exception ignored) {
            }
            return null;
        }

        private static HttpRequest removeHeader(HttpRequest req, String name) {
            return updateHeader(req, name, null, true);
        }

        private static HttpRequest setOrReplaceHeader(HttpRequest req, String name, String value) {
            return updateHeader(req, name, value, false);
        }

        /**
         * Update headers without relying on Montoya header mutation helpers (which can vary by version).
         * We rebuild the raw request and create a new HttpRequest from the original HttpService.
         */
        private static HttpRequest updateHeader(HttpRequest req, String headerName, String headerValue, boolean remove) {
            if (req == null || headerName == null || headerName.isEmpty()) return req;
            try {
                String raw = req.toString();
                if (raw == null) return req;

                String[] lines = raw.split("\\r?\\n", -1);
                StringBuilder out = new StringBuilder(raw.length() + 64);

                // 1) request line
                int i = 0;
                if (lines.length > 0) {
                    out.append(lines[0]).append("\r\n");
                    i = 1;
                }

                // 2) headers until blank line
                boolean sawBlank = false;
                for (; i < lines.length; i++) {
                    String line = lines[i];
                    if (line == null) line = "";
                    if (line.isEmpty()) {
                        sawBlank = true;
                        // append updated header (if adding/replacing) before the blank line
                        if (!remove && headerValue != null) {
                            out.append(headerName).append(": ").append(headerValue).append("\r\n");
                        }
                        out.append("\r\n");
                        i++;
                        break;
                    }
                    int colon = line.indexOf(':');
                    if (colon > 0) {
                        String n = line.substring(0, colon).trim();
                        if (n.equalsIgnoreCase(headerName)) {
                            // skip (remove or replace later)
                            continue;
                        }
                    }
                    out.append(line).append("\r\n");
                }

                // If there was no blank line, still append one and optional header
                if (!sawBlank) {
                    if (!remove && headerValue != null) {
                        out.append(headerName).append(": ").append(headerValue).append("\r\n");
                    }
                    out.append("\r\n");
                }

                // 3) body (rest)
                for (; i < lines.length; i++) {
                    out.append(lines[i]);
                    if (i < lines.length - 1) out.append("\r\n");
                }

                return HttpRequest.httpRequest(req.httpService(), out.toString());
            } catch (Exception e) {
                return req;
            }
        }
	private static HttpRequest updateRequestLine(HttpRequest req, String newMethod, String newPath) {
		try {
			String raw = req.toString();
			int headerEnd = raw.indexOf("\r\n\r\n");
			String head = headerEnd >= 0 ? raw.substring(0, headerEnd) : raw;
			String[] lines = head.split("\r\n");
			if (lines.length == 0) return req;
			String[] parts = lines[0].split(" ");
			String version = parts.length >= 3 ? parts[2] : "HTTP/1.1";
			lines[0] = newMethod + " " + newPath + " " + version;
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < lines.length; i++) {
				if (i > 0) sb.append("\r\n");
				sb.append(lines[i]);
			}
			if (headerEnd >= 0) {
				sb.append("\r\n\r\n");
				sb.append(raw.substring(headerEnd + 4));
			}
			return HttpRequest.httpRequest(req.httpService(), sb.toString());
		} catch (Exception e) {
			return req;
		}
	}

	private static HttpRequest mutateContentTypeAndBody(HttpRequest base, String contentType, String newBody) {
        HttpRequest r = setOrReplaceHeader(base, "Content-Type", contentType);
        if (newBody != null) {
            return r.withBody(ByteArray.byteArray(newBody));
        }
        return r;
    }

    private static String buildApplicationGraphqlBody(HttpRequest base) {
        Map<String, Object> map = tryParseJson(base.body() != null ? base.body().toString() : "");
        Object q = map.get("query");
        if (q == null) return base.body() != null ? base.body().toString() : "";
        return String.valueOf(q);
    }

    private static String buildFormUrlencodedBody(HttpRequest base) {
        Map<String, Object> map = tryParseJson(base.body() != null ? base.body().toString() : "");
        String query = map.get("query") != null ? String.valueOf(map.get("query")) : "";
        String variables = map.get("variables") != null ? Json.compact(map.get("variables")) : "";
        String op = map.get("operationName") != null ? String.valueOf(map.get("operationName")) : "";

        // Important: encode newlines/tabs/spaces correctly.
        StringBuilder sb = new StringBuilder();
        sb.append("query=").append(urlenc(query));
        if (!variables.isBlank()) sb.append("&variables=").append(urlenc(variables));
        if (!op.isBlank()) sb.append("&operationName=").append(urlenc(op));
        return sb.toString();
    }

    /**
     * application/x-www-form-urlencoded variant that only sends the GraphQL "query" parameter.
     */
    private static String buildFormUrlencodedBodyQueryOnly(HttpRequest base) {
        Map<String, Object> map = tryParseJson(base.body() != null ? base.body().toString() : "");
        String query = map.get("query") != null ? String.valueOf(map.get("query")) : "";
        return "query=" + urlenc(query);
    }

    /**
     * application/x-www-form-urlencoded variant that places the whole GraphQL JSON payload into one form field.
     * Common server patterns accept this as: graphql=<json> or payload=<json>.
     */
    private static String buildFormUrlencodedBodyGraphqlJson(HttpRequest base) {
        String body = base.body() != null ? base.body().toString() : "";
        // Keep it compact to reduce whitespace-related parsing differences.
        Map<String, Object> map = tryParseJson(body);
        String compact = map.isEmpty() ? body : Json.compact(map);
        return "graphql=" + urlenc(compact);
    }

    private static String buildMultipartBody(HttpRequest base, String boundary) {
        Map<String, Object> map = tryParseJson(base.body() != null ? base.body().toString() : "");
        String query = map.get("query") != null ? String.valueOf(map.get("query")) : "";
        String variables = map.get("variables") != null ? Json.compact(map.get("variables")) : "";
        String op = map.get("operationName") != null ? String.valueOf(map.get("operationName")) : "";

        String crlf = "\r\n";
        StringBuilder b = new StringBuilder();
        // query
        b.append("--").append(boundary).append(crlf);
        b.append("Content-Disposition: form-data; name=\"query\"").append(crlf).append(crlf);
        b.append(query).append(crlf);
        // variables
        if (!variables.isBlank()) {
            b.append("--").append(boundary).append(crlf);
            b.append("Content-Disposition: form-data; name=\"variables\"").append(crlf).append(crlf);
            b.append(variables).append(crlf);
        }
        // operationName
        if (!op.isBlank()) {
            b.append("--").append(boundary).append(crlf);
            b.append("Content-Disposition: form-data; name=\"operationName\"").append(crlf).append(crlf);
            b.append(op).append(crlf);
        }
        b.append("--").append(boundary).append("--").append(crlf);
        return b.toString();
    }

    private static Variant buildGetVariant(HttpRequest base, String name, boolean includeVariables) {
        try {
            String body = base.body().toString();
            if (body == null || body.isBlank()) return null;
            var m = com.gqlasa.util.Json.parseMap(body);
            Object qObj = m.get("query");
            if (!(qObj instanceof String q) || q.isBlank()) return null;
            StringBuilder qs = new StringBuilder();
            qs.append("query=").append(urlenc(q));
            Object op = m.get("operationName");
            if (op instanceof String opn && !opn.isBlank()) {
                qs.append("&operationName=").append(urlenc(opn));
            }
            if (includeVariables) {
                Object vars = m.get("variables");
                if (vars != null) {
                    String compact = com.gqlasa.util.Json.compact(vars);
                    if (compact != null && !compact.isBlank() && !compact.equals("null")) {
                        qs.append("&variables=").append(urlenc(compact));
                    }
                }
            }
            String path = base.path();
            int qi = path.indexOf("?");
            if (qi >= 0) path = path.substring(0, qi);
            String newPath = path + "?" + qs;
            HttpRequest req = updateRequestLine(base, "GET", newPath);
            req = updateHeader(req, "Content-Type", null, true);
            req = updateHeader(req, "Content-Length", null, true);
            req = req.withBody("");
            return new Variant(name, req, includeVariables ? "GET variables" : "GET query");
        } catch (Exception e) {
            return null;
        }
    }

    private static String urlenc(String s) {
        return URLEncoder.encode(s == null ? "" : s, StandardCharsets.UTF_8);
    }

    // ------------------------- Explanation -------------------------

    private String buildExplainHtml(Row r) {
        if (r == null) {
            return "<html><body style='font-family:sans-serif;font-size:12px;'><i>Select a row to see details.</i></body></html>";
        }

        String scenario = esc(r.variant);
        String mode = esc(r.mode);
        String potential = esc(r.potential);
        String notes = esc(r.notes);

        // Find baseline row from the current table model
        Row base = null;
        for (int i = 0; i < model.getRowCount(); i++) {
            Row candidate = model.getRow(i);
            if (candidate != null && candidate.isBaseline) {
                base = candidate;
                break;
            }
        }

        String baselineCmp;
        if (base == null || r.isBaseline) {
            baselineCmp = "<div class='section'><h3>Baseline comparison</h3><p>N/A</p></div>";
        } else {
            String statusCmp = base.status + " → " + r.status;
            String lenCmp = base.length + " → " + r.length;
            String simTxt = r.similar ? "Similar" : "Different";
            baselineCmp = "<div class='section'><h3>Baseline comparison</h3>" +
                    "<p><b>Status:</b> " + esc(statusCmp) + "</p>" +
                    "<p><b>Length:</b> " + esc(lenCmp) + "</p>" +
                    "<p><b>Similarity:</b> " + esc(simTxt) + "</p>" +
                    "</div>";
        }

        String interpretation;
        if ("Yes".equalsIgnoreCase(r.potential)) {
            interpretation = "Request variant appears to behave equivalently to baseline. This may indicate missing CSRF protections (or weak Origin/Referer validation, overly-permissive content-type handling, etc.).";
        } else if (r.isBaseline) {
            interpretation = "Baseline request/response captured. Variants are compared against this.";
        } else {
            interpretation = "Variant behavior differs from baseline or returned errors. This often indicates CSRF protections or strict parsing requirements.";
        }

        String html = "<html><head><style>" +
                "body{font-family:sans-serif;font-size:12px;}" +
                ".section{margin-bottom:10px;padding:8px;border:1px solid #ddd;border-radius:6px;}" +
                ".section h3{margin:0 0 6px 0;font-size:12px;}" +
                "p{margin:4px 0;}" +
                "</style></head><body>" +
                "<div class='section'><h3>Attack explanation</h3>" +
                "<p><b>Scenario:</b> " + scenario + "</p>" +
                "<p><b>Mode:</b> " + mode + "</p>" +
                "</div>" +
                baselineCmp +
                "<div class='section'><h3>Reason</h3>" +
                "<p>" + notes + "</p>" +
                "</div>" +
                "<div class='section'><h3>Interpretation</h3>" +
                "<p><b>Potential CSRF:</b> " + potential + "</p>" +
                "<p>" + esc(interpretation) + "</p>" +
                "</div>" +
                "</body></html>";
        return html;
    }


    private static String esc(String s) {
        return escape(s);
    }

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    // ------------------------- Paging -------------------------

    private void refreshPager() {
        applyPaging();
    }

    private int maxPageIndex() {
        int total = model.getRowCount();
        if (total <= PAGE_SIZE) return 0;
        return (total - 1) / PAGE_SIZE;
    }

    private void applyPaging() {
        int max = maxPageIndex();
        pageIndex = Math.max(0, Math.min(pageIndex, max));

        int start = pageIndex * PAGE_SIZE;
        int end = Math.min(model.getRowCount(), start + PAGE_SIZE);

        sorter.setRowFilter(new RowFilter<>() {
            @Override
            public boolean include(Entry<? extends CsrfTableModel, ? extends Integer> entry) {
                int idx = entry.getIdentifier();
                return idx >= start && idx < end;
            }
        });

        lblPager.setText("Page " + (pageIndex + 1) + "/" + (max + 1) + " (" + model.getRowCount() + " rows)");
        btnPrev.setEnabled(pageIndex > 0);
        btnNext.setEnabled(pageIndex < max);

        // Keep selection visible
        if (table.getSelectedRow() < 0 && model.getRowCount() > 0) {
            selectRowIfAny(start);
        }
    }

    // ------------------------- Types -------------------------

    private static final class ScanOptions {
        int maxVariants;
        int concurrency;
        int timeoutMs;
        int retries;
        boolean allowGraphqlErrors;
        boolean compareDataOnly;
        boolean includeExtensions;
        boolean testHeaders;
        boolean fuzzContentType;
    }

    private static final class Variant {
        final String name;
        final HttpRequest request;
        final String note;

        Variant(String name, HttpRequest request, String note) {
            this.name = name;
            this.request = request;
            this.note = note;
        }
    }

    private static final class Row {
        int index;
        String variant;
        String method;
        String mode; // scenario / mode label
        int status;
        int length;
        boolean isBaseline;
        boolean similar;
        String potential;
        String notes;
        HttpRequest request;
        HttpResponse response;
    }

    private static final class CsrfTableModel extends AbstractTableModel {
        private final String[] cols = {"Scenario", "Method", "Status", "Len", "Potential CSRF", "Notes"};
        private final List<Row> rows = new ArrayList<>();

        void clearAll() {
            rows.clear();
            fireTableDataChanged();
        }

        void addRow(Row r) {
            rows.add(r);
            fireTableRowsInserted(rows.size() - 1, rows.size() - 1);
        }

        Row getRow(int i) {
            if (i < 0 || i >= rows.size()) return null;
            return rows.get(i);
        }

        boolean isPotentialYes(int modelRow) {
            Row r = getRow(modelRow);
            return r != null && "Yes".equalsIgnoreCase(r.potential);
        }

        @Override
        public int getRowCount() { return rows.size(); }

        @Override
        public int getColumnCount() { return cols.length; }

        @Override
        public String getColumnName(int column) { return cols[column]; }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            Row r = rows.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> r.variant; // scenario name
                case 1 -> r.method;
                case 2 -> r.status;
                case 3 -> r.length;
                case 4 -> r.potential;
                case 5 -> r.notes;
                default -> "";
            };
        }
    }
}
