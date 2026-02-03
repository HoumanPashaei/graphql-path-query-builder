package com.gqlsurfmapper.gqlasa;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import java.awt.*;

public class GeneralConfigPanel extends JPanel
{
    public GeneralConfigPanel(MontoyaApi api)
    {
        super(new BorderLayout());

        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(6,6,6,6);
        c.fill = GridBagConstraints.HORIZONTAL;

        JTextField scheme = new JTextField("https");
        JTextField host = new JTextField();
        JTextField port = new JTextField("443");
        JTextField endpointPath = new JTextField(); // required

        int r = 0;

        c.gridx=0; c.gridy=r; c.weightx=0; form.add(new JLabel("Scheme (http/https)"), c);
        c.gridx=1; c.gridy=r; c.weightx=1; form.add(scheme, c); r++;

        c.gridx=0; c.gridy=r; c.weightx=0; form.add(new JLabel("Host"), c);
        c.gridx=1; c.gridy=r; c.weightx=1; form.add(host, c); r++;

        c.gridx=0; c.gridy=r; c.weightx=0; form.add(new JLabel("Port"), c);
        c.gridx=1; c.gridy=r; c.weightx=1; form.add(port, c); r++;

        c.gridx=0; c.gridy=r; c.weightx=0; form.add(new JLabel("GraphQL Endpoint Path (required)"), c);
        c.gridx=1; c.gridy=r; c.weightx=1; form.add(endpointPath, c); r++;

        JTextArea note = new JTextArea(
            "Phase 2 plan:\n" +
            "- Headers table (key/value + enable/disable)\n" +
            "- Content-Type selection\n" +
            "- 'Use selected request as Base Target'\n" +
            "- Validation (endpoint path required)\n"
        );
        note.setEditable(false);
        note.setLineWrap(true);
        note.setWrapStyleWord(true);

        add(form, BorderLayout.NORTH);
        add(new JScrollPane(note), BorderLayout.CENTER);
    }
}
