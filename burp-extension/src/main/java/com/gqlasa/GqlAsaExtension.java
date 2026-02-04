package com.gqlasa;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.BurpExtension;
import com.gqlasa.ui.MainPanel;
import com.gqlasa.ui.querybuilder.IntrospectionImportProvider;

import javax.swing.*;

public class GqlAsaExtension implements BurpExtension {
    public static volatile MontoyaApi API;

    @Override
    public void initialize(MontoyaApi api) {
        API = api;
        api.extension().setName("GQL-ASA");
        api.logging().logToOutput("GQL-ASA loaded.");

        api.userInterface().registerContextMenuItemsProvider(new IntrospectionImportProvider(api));

        SwingUtilities.invokeLater(() ->
                api.userInterface().registerSuiteTab("GQL-ASA", new MainPanel())
        );
    }
}
