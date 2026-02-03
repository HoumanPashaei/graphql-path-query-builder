package com.gqlasa.ui.querybuilder;

import com.gqlasa.model.AppState;
import com.gqlasa.model.GeneralConfig;
import com.gqlasa.model.HeaderKV;
import com.gqlasa.util.Strings;

import javax.swing.*;
import java.awt.*;
import java.util.LinkedHashMap;
import java.util.Map;

public class GeneralConfigPanel extends JPanel {
    private final GeneralConfig cfg = AppState.get().config;

    // Editable combos with common values
    private final JComboBox<String> scheme = editableCombo(new String[]{"https", "http"}, cfg.scheme, 10);
    private final JTextField host = new JTextField(cfg.host, 26);
    private final JComboBox<String> port = editableCombo(new String[]{"443", "80"}, String.valueOf(cfg.port), 10);
    private final JComboBox<String> endpoint = editableCombo(
            new String[]{
                    "/graphql",
                    "/api",
                    "/api/graphql",
                    "/graphql/api",
                    "/graphql/graphql",
                    "/v1/graphql",
                    "/api/v1",
                    "/api/v1/graphql",
                    "/graphql/api/v1",
                    "v1/graphql/graphql" // requested (no leading slash)
            },
            cfg.endpointPath, 26
    );

    private final JComboBox<String> method = new JComboBox<>(new String[]{"POST","GET"});
    private final JComboBox<String> contentType = editableCombo(
            new String[]{"application/json", "application/graphql", "application/x-www-form-urlencoded"},
            cfg.contentType, 26
    );

    private final HeadersTableModel headersModel = new HeadersTableModel(cfg.headers);

    // Quick-add header controls
    private final JComboBox<String> quickHeaderKey = editableCombo(commonHeaderKeys(), "", 20);
    private final JComboBox<String> quickHeaderValue = editableCombo(new String[]{""}, "", 40);

    private final JLabel status = new JLabel(" ");

    private final Timer statusClear = new Timer(2500, e -> status.setText(" "));

    public GeneralConfigPanel() {
        super(new BorderLayout(10,10));

        statusClear.setRepeats(false);

        // Put dropdown arrow on the LEFT: use RTL orientation for comboboxes
        applyLeftArrow(scheme);
        applyLeftArrow(port);
        applyLeftArrow(endpoint);
        applyLeftArrow(contentType);
        applyLeftArrow(method);
        applyLeftArrow(quickHeaderKey);
        applyLeftArrow(quickHeaderValue);

        method.setSelectedItem(cfg.method == null ? "POST" : cfg.method.toUpperCase());
        if (Strings.isBlank(cfg.scheme)) scheme.setSelectedItem("https");
        if (Strings.isBlank(cfg.contentType)) contentType.setSelectedItem("application/json");

        // When selecting a common header, suggest common values
        quickHeaderKey.addActionListener(e -> updateQuickValueSuggestions());

        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints gc = new GridBagConstraints();
        gc.insets = new Insets(4,4,4,4);
        gc.anchor = GridBagConstraints.WEST;

        int r = 0;
        addRow(form, gc, r++, "Scheme", scheme);
        addRow(form, gc, r++, "Host", host);
        addRow(form, gc, r++, "Port", port);
        addRow(form, gc, r++, "Endpoint path", endpoint);
        addRow(form, gc, r++, "Method", method);
        addRow(form, gc, r++, "Content-Type", contentType);

        JTable table = new JTable(headersModel);
        table.setFillsViewportHeight(true);

        // Quick add panel
        JButton quickAdd = new JButton("Add");
        quickAdd.addActionListener(e -> {
            String k = getComboText(quickHeaderKey).trim();
            String v = getComboText(quickHeaderValue);
            if (Strings.isBlank(k)) {
                showStatus("Header name is empty.", true);
                return;
            }
            addHeaderRow(table, k, v);
            showStatus("Header added: " + k, false);
        });

        JPanel quick = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 6));
        quick.add(new JLabel("Quick add:"));
        quick.add(new JLabel("Header"));
        quick.add(quickHeaderKey);
        quick.add(new JLabel("Value"));
        quick.add(quickHeaderValue);
        quick.add(quickAdd);

        JButton addHeader = new JButton("Add Custom Header");
        JButton removeHeader = new JButton("Remove selected");
        JButton save = new JButton("Save");

        addHeader.addActionListener(e -> {
            addHeaderRow(table, "", "");
            showStatus("Added custom header row.", false);
        });

        removeHeader.addActionListener(e -> {
            int row = table.getSelectedRow();
            headersModel.removeRow(row);
            showStatus("Removed selected header row.", false);
        });

        save.addActionListener(e -> saveToState());

        JPanel headerButtons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        headerButtons.add(addHeader);
        headerButtons.add(removeHeader);
        headerButtons.add(save);

        JPanel headersPanel = new JPanel(new BorderLayout(6,6));
        headersPanel.setBorder(BorderFactory.createTitledBorder("Headers / Token Management"));
        headersPanel.add(new JScrollPane(table), BorderLayout.CENTER);

        JPanel bottom = new JPanel(new BorderLayout(6,6));
        bottom.add(quick, BorderLayout.NORTH);
        bottom.add(headerButtons, BorderLayout.CENTER);

        status.setFont(status.getFont().deriveFont(Font.BOLD, 14f));
        status.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
        bottom.add(status, BorderLayout.SOUTH);

        headersPanel.add(bottom, BorderLayout.SOUTH);

        add(form, BorderLayout.NORTH);
        add(headersPanel, BorderLayout.CENTER);

        setBorder(BorderFactory.createEmptyBorder(8,8,8,8));

        updateQuickValueSuggestions();
    }

    private void addRow(JPanel form, GridBagConstraints gc, int row, String label, JComponent comp) {
        gc.gridx = 0; gc.gridy = row; gc.weightx = 0; gc.fill = GridBagConstraints.NONE;
        form.add(new JLabel(label + ":"), gc);
        gc.gridx = 1; gc.gridy = row; gc.weightx = 1; gc.fill = GridBagConstraints.HORIZONTAL;
        form.add(comp, gc);
    }

    private void saveToState() {
        GeneralConfig c = AppState.get().config;

        c.scheme = Strings.nullToEmpty(getComboText(scheme)).trim();
        c.host = Strings.nullToEmpty(host.getText()).trim();
        c.endpointPath = Strings.nullToEmpty(getComboText(endpoint)).trim();
        c.contentType = Strings.nullToEmpty(getComboText(contentType)).trim();
        c.method = String.valueOf(method.getSelectedItem());

        try {
            c.port = Integer.parseInt(getComboText(port).trim());
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Port must be a number.", "Invalid config", JOptionPane.ERROR_MESSAGE);
            return;
        }

        showStatus("Saved General Config.", false);
    }

    private void addHeaderRow(JTable table, String key, String value) {
        headersModel.addRow();
        int newRow = headersModel.getRowCount() - 1;

        HeaderKV kv = cfg.headers.get(newRow);
        kv.key = key == null ? "" : key;
        kv.value = value == null ? "" : value;

        headersModel.fireTableRowsUpdated(newRow, newRow);

        table.getSelectionModel().setSelectionInterval(newRow, newRow);
        Rectangle rect = table.getCellRect(newRow, 0, true);
        table.scrollRectToVisible(rect);

        table.requestFocusInWindow();
    }

    private void showStatus(String msg, boolean error) {
        status.setForeground(error ? new Color(160, 0, 0) : new Color(0, 110, 0));
        status.setText(msg);
        statusClear.restart();
    }

    private static JComboBox<String> editableCombo(String[] values, String initial, int columnsApprox) {
        JComboBox<String> cb = new JComboBox<>(values);
        cb.setEditable(true);
        if (initial != null && !initial.isBlank()) cb.setSelectedItem(initial);
        Dimension d = cb.getPreferredSize();
        d.width = Math.max(d.width, columnsApprox * 10);
        cb.setPreferredSize(d);
        return cb;
    }

    private static void applyLeftArrow(JComboBox<String> cb) {
        // RTL moves the arrow button to the left in Swing
        cb.setComponentOrientation(ComponentOrientation.RIGHT_TO_LEFT);

        // Keep displayed text left-aligned (both list + editor field)
        cb.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
                JLabel l = (JLabel) super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                l.setHorizontalAlignment(SwingConstants.LEFT);
                return l;
            }
        });

        // Editable combos use a JTextField editor; force left alignment and LTR text direction
        try {
            Component ec = cb.getEditor().getEditorComponent();
            if (ec instanceof JTextField tf) {
                tf.setComponentOrientation(ComponentOrientation.LEFT_TO_RIGHT);
                tf.setHorizontalAlignment(SwingConstants.LEFT);
            }
        } catch (Exception ignored) {
        }
    }

    private static String getComboText(JComboBox<String> cb) {
        Object item = cb.getEditor() != null ? cb.getEditor().getItem() : cb.getSelectedItem();
        return item == null ? "" : item.toString();
    }

    private static String[] commonHeaderKeys() {
        return new String[]{
                "Authorization",
                "Cookie",
                "X-API-Key",
                "X-CSRF-Token",
                "X-Requested-With",
                "User-Agent",
                "Accept",
                "Content-Type",
                "Referer",
                "Origin"
        };
    }

    private void updateQuickValueSuggestions() {
        String key = getComboText(quickHeaderKey).trim();

        Map<String, String[]> map = new LinkedHashMap<>();
        map.put("Authorization", new String[]{"Bearer REPLACE_ME", "Basic REPLACE_ME", "ApiKey REPLACE_ME", "Token REPLACE_ME", "REPLACE_ME"});
        map.put("Cookie", new String[]{"REPLACE_ME"});
        map.put("X-API-Key", new String[]{"REPLACE_ME"});
        map.put("X-CSRF-Token", new String[]{"REPLACE_ME"});
        map.put("X-Requested-With", new String[]{"XMLHttpRequest", "REPLACE_ME"});
        map.put("User-Agent", userAgentValues());
        map.put("Accept", new String[]{"application/json", "*/*"});
        map.put("Content-Type", new String[]{"application/json", "application/graphql", "application/x-www-form-urlencoded"});
        map.put("Referer", new String[]{"REPLACE_ME"});
        map.put("Origin", new String[]{"REPLACE_ME"});

        String[] vals = map.getOrDefault(key, new String[]{"REPLACE_ME"});

        DefaultComboBoxModel<String> model = new DefaultComboBoxModel<>(vals);
        quickHeaderValue.setModel(model);
        quickHeaderValue.setEditable(true);
        quickHeaderValue.setSelectedItem(vals.length > 0 ? vals[0] : "");
        applyLeftArrow(quickHeaderValue);
    }

    private static String[] userAgentValues() {
        return new String[]{
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 13.6; rv:123.0) Gecko/20100101 Firefox/123.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
                "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
                "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
                "Mozilla/5.0",
                "REPLACE_ME"
        };
    }
}
