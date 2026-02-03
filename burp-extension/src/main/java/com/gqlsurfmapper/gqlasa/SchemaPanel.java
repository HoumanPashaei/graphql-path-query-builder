package com.gqlsurfmapper.gqlasa;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import java.awt.*;

public class SchemaPanel extends JPanel
{
    public SchemaPanel(MontoyaApi api)
    {
        super(new BorderLayout());

        JTextArea info = new JTextArea(
            "Phase 2 plan:\n" +
            "- Import schema from file\n" +
            "- Paste schema JSON\n" +
            "- Fetch introspection using Base Target / selected request\n"
        );
        info.setEditable(false);
        info.setLineWrap(true);
        info.setWrapStyleWord(true);

        add(new JScrollPane(info), BorderLayout.CENTER);
    }
}
