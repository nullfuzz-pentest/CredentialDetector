package creddetector;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

/**
 * Montoya extension entry point.
 *
 * Detects credentials / secrets in HTTP responses using a broad list of
 * keywords (with separator variants '_', '-', '.'), lists them in its own
 * tab and highlights the matches in the response viewer.
 */
public class CredentialDetectorExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Credential Detector");

        CredentialDetectorTab tab = new CredentialDetectorTab(api);
        api.userInterface().registerSuiteTab("Credential Detector", tab.getUiComponent());

        api.http().registerHttpHandler(new CredentialHttpHandler(api, tab));

        api.logging().logToOutput("[+] Credential Detector loaded.");
        api.logging().logToOutput("[+] 'Credential Detector' tab added.");
        api.logging().logToOutput("[+] Scanning HTTP responses for credentials.");
    }
}
