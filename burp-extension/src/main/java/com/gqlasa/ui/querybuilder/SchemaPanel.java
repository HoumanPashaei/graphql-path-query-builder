package com.gqlasa.ui.querybuilder;

import com.gqlasa.core.SchemaLoader;
import com.gqlasa.core.schema.SchemaIndex;
import com.gqlasa.model.AppState;
import com.gqlasa.util.Json;

import javax.swing.*;
import javax.swing.SwingWorker;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.io.File;
import java.nio.file.Files;
import java.util.concurrent.atomic.AtomicLong;

public class SchemaPanel extends JPanel {

    private JTextArea schemaArea;
    private final JLabel status = new JLabel("Schema: not loaded");

    private final Timer applyDebounce;
    private volatile boolean suppressDocEvents = false;

    private SwingWorker<Void, Void> validatorWorker = null;
    private final AtomicLong validationSeq = new AtomicLong(0);

    public SchemaPanel() {

        super(new BorderLayout(8, 8));

        schemaArea = new JTextArea();

        schemaArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        schemaArea.setLineWrap(false);
        schemaArea.setWrapStyleWord(false);
        schemaArea.setText(AppState.get().schemaJson);

        JButton loadFile = new JButton("Load from file...");
        JButton format = new JButton("Format (pretty)");
        JButton clear = new JButton("Clear");

        loadFile.addActionListener(e -> onLoadFileAsync());
        format.addActionListener(e -> onFormatAsync());
        clear.addActionListener(e -> {
            suppressDocEvents = true;
            try { schemaArea.setText(""); } finally { suppressDocEvents = false; }
            applySchemaToState("");
        });

        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        top.add(loadFile);
        top.add(format);
        top.add(clear);

        applyDebounce = new Timer(650, e -> applySchemaToState(schemaArea.getText()));
        applyDebounce.setRepeats(false);

        schemaArea.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { scheduleApply(); }
            @Override public void removeUpdate(DocumentEvent e) { scheduleApply(); }
            @Override public void changedUpdate(DocumentEvent e) { scheduleApply(); }
        });

        add(top, BorderLayout.NORTH);
        add(new JScrollPane(schemaArea), BorderLayout.CENTER);
        add(status, BorderLayout.SOUTH);

        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        refreshStatusAsync();
    }

    private void scheduleApply() {
        if (suppressDocEvents) return;
        applyDebounce.restart();
        status.setText("Schema: pending apply...");
    }

    private void onLoadFileAsync() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select schema JSON (introspection)");
        int res = chooser.showOpenDialog(this);
        if (res != JFileChooser.APPROVE_OPTION) return;

        File f = chooser.getSelectedFile();

        ProgressDialog pd = new ProgressDialog(SwingUtilities.getWindowAncestor(this), "Loading Schema (This may take a few minutes on large Schemas)...");
        pd.showDialog();

        SwingWorker<String, Void> worker = new SwingWorker<>() {
            @Override protected String doInBackground() throws Exception {
                return Files.readString(f.toPath());
            }

            @Override protected void done() {
                try {
                    String raw = get();
                    suppressDocEvents = true;
                    try {
                        schemaArea.setText(raw);
                        schemaArea.setCaretPosition(0);
                    } finally {
                        suppressDocEvents = false;
                    }
                    applySchemaToState(raw);
                    pd.complete("Loaded.");
                } catch (Exception ex) {
                    pd.complete("Failed.");
                    JOptionPane.showMessageDialog(SchemaPanel.this, "Failed to Read file: " + ex.getMessage(),
                            "Schema Load Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        };
        worker.execute();
    }

    private void onFormatAsync() {
        String current = schemaArea.getText();
        if (current == null || current.trim().isEmpty()) {
            JOptionPane.showMessageDialog(this, "Schema is Empty.", "Format", JOptionPane.ERROR_MESSAGE);
            return;
        }

        ProgressDialog pd = new ProgressDialog(SwingUtilities.getWindowAncestor(this), "Formatting Schema (This may take a few minutes on large schemas)...");
        pd.showDialog();

        SwingWorker<String, Void> worker = new SwingWorker<>() {
            @Override protected String doInBackground() {
                try {
                    Object node = Json.parse(current);
                    if (node == null) return current;
                    return Json.toPrettyString(node);
                } catch (Exception e) {
                    return current;
                }
            }

            @Override protected void done() {
                try {
                    String pretty = get();
                    suppressDocEvents = true;
                    try {
                        schemaArea.setText(pretty);
                        schemaArea.setCaretPosition(0);
                    } finally {
                        suppressDocEvents = false;
                    }
                    applySchemaToState(pretty);
                    pd.complete("Formatted.");
                } catch (Exception ex) {
                    pd.complete("Failed.");
                    JOptionPane.showMessageDialog(SchemaPanel.this, "Format failed: " + ex.getMessage(),
                            "Format", JOptionPane.ERROR_MESSAGE);
                }
            }
        };
        worker.execute();
    }

    private void applySchemaToState(String schema) {
        AppState st = AppState.get();
        st.schemaJson = schema == null ? "" : schema;
        st.schemaRevision++;
        st.lastResults.clear();
        refreshStatusAsync();
    }

    private void refreshStatusAsync() {
        String schemaJson = AppState.get().schemaJson;
        if (schemaJson == null || schemaJson.trim().isEmpty()) {
            AppState st = AppState.get();
            if (st.schemaAutoFetchFailed) {
                String msg = (st.schemaAutoFetchMessage == null || st.schemaAutoFetchMessage.isBlank())
                        ? "Schema: not loaded (introspection failed — please import schema)"
                        : st.schemaAutoFetchMessage;
                status.setText(msg);
            } else {
                status.setText("Schema: not loaded");
            }
            return;
        }

        // Clear any previous auto-fetch error once we have schema content
        AppState.get().schemaAutoFetchFailed = false;
        AppState.get().schemaAutoFetchMessage = "";

        if (validatorWorker != null && !validatorWorker.isDone()) {
            validatorWorker.cancel(true);
        }

        long seq = validationSeq.incrementAndGet();
        status.setText("Schema: validating...");

        validatorWorker = new SwingWorker<>() {
            @Override protected Void doInBackground() {
                try {
                    SchemaIndex idx = SchemaLoader.loadFromIntrospectionJson(schemaJson);
                    if (isCancelled()) return null;
                    int typeCount = idx.types == null ? 0 : idx.types.size();
                    SwingUtilities.invokeLater(() -> {
                        if (validationSeq.get() != seq) return;
                        status.setText("Schema: loaded (types: " + typeCount + ", queryType: " + idx.queryTypeName + ")");
                    });
                } catch (Exception e) {
                    SwingUtilities.invokeLater(() -> {
                        if (validationSeq.get() != seq) return;
                        status.setText("Schema: loaded (invalid/unsupported JSON)");
                    });
                }
                return null;
            }
        };

        validatorWorker.execute();
    }


    public void loadSchemaFromState() {
        // When schema is injected programmatically (auto-introspection), we want the UI
        // to reflect it immediately without relying on debounce/document events.
        String s = com.gqlasa.model.AppState.get().schemaJson;
        suppressDocEvents = true;
        try {
            schemaArea.setText(s == null ? "" : s);
            schemaArea.setCaretPosition(0);
        } finally {
            suppressDocEvents = false;
        }
        applySchemaToState(schemaArea.getText());
    }
}
