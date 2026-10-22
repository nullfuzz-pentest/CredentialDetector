package creddetector;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;

/**
 * Analyzes every HTTP response passing through Burp and, if it detects
 * credentials, adds a row to the tab. Deduplicates by URL + terms.
 */
public class CredentialHttpHandler implements HttpHandler {

    private final MontoyaApi api;
    private final CredentialDetectorTab tab;
    private final Set<String> seen = new LinkedHashSet<>();
    private final AtomicInteger seenResponses = new AtomicInteger(0);
    private final SimpleDateFormat timeFmt = new SimpleDateFormat("HH:mm:ss");

    public CredentialHttpHandler(MontoyaApi api, CredentialDetectorTab tab) {
        this.api = api;
        this.tab = tab;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        // No modificamos las peticiones.
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        try {
            process(responseReceived);
        } catch (Throwable t) {
            api.logging().logToError("Error processing response: " + t);
        }
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private void process(HttpResponseReceived responseReceived) {
        tab.bumpSeen(seenResponses.incrementAndGet());

        String responseText = responseReceived.toString();
        if (responseText == null || responseText.isEmpty()) {
            return;
        }

        String normalized = responseText.replace("\r\n", "\n").replace("\r", "\n");
        Matcher matcher = CredentialRegex.PATTERN.matcher(normalized);
        Set<String> terms = new LinkedHashSet<>();       // for display
        List<Detection.Finding> findings = new ArrayList<>();
        int count = 0;
        while (matcher.find()) {
            String term = matcher.group();
            terms.add(term.toLowerCase());
            int start = matcher.start();
            int end = matcher.end();
            String context = extractLine(normalized, start);
            String value = extractValue(normalized, end);
            findings.add(new Detection.Finding(term, value, context));
            count++;
        }
        if (count == 0) {
            return;
        }

        HttpRequest request = responseReceived.initiatingRequest();
        String url = (request != null) ? request.url() : "";
        String method = (request != null) ? request.method() : "";
        String host = (request != null && request.httpService() != null)
            ? request.httpService().host() : "";

        String termsList = String.join(", ", terms);

        String dedupKey = url + "||" + termsList;
        if (seen.contains(dedupKey)) {
            return;
        }
        seen.add(dedupKey);

        HttpRequestResponse rr = HttpRequestResponse.httpRequestResponse(request, responseReceived);

        Detection detection = new Detection(
            timeFmt.format(new Date()),
            method,
            url,
            host,
            termsList,
            count,
            rr,
            responseText,
            findings
        );
        tab.addDetection(detection);

        api.logging().logToOutput(
            "[!] Potential credentials at: " + url + " (" + count + " matches)");
    }

    /** Returns the full (trimmed) line that contains the given position. */
    private static String extractLine(String text, int pos) {
        int lineStart = text.lastIndexOf('\n', Math.max(0, pos - 1)) + 1;
        int lineEnd = text.indexOf('\n', pos);
        if (lineEnd < 0) {
            lineEnd = text.length();
        }
        String line = text.substring(lineStart, lineEnd).trim();
        // Limit so we don't dump huge lines into the CSV.
        if (line.length() > 300) {
            line = line.substring(0, 300) + "...";
        }
        return line;
    }

    /**
     * Tries to extract the value associated with the credential: what follows
     * the term after a typical separator (= : "). Returns "" if no clear
     * value is found.
     */
    private static String extractValue(String text, int termEnd) {
        int i = termEnd;
        int n = text.length();
        // Skip spaces and common separators (= : " ' > space).
        while (i < n) {
            char c = text.charAt(i);
            if (c == ' ' || c == '\t' || c == '=' || c == ':' || c == '"'
                || c == '\'' || c == '>' || c == '\u00a0') {
                i++;
            } else {
                break;
            }
        }
        int start = i;
        // The value ends at end of line or at a closing delimiter.
        while (i < n) {
            char c = text.charAt(i);
            if (c == '\n' || c == '"' || c == '\'' || c == '<'
                || c == ',' || c == ';' || c == '}') {
                break;
            }
            i++;
        }
        String value = text.substring(start, i).trim();
        if (value.length() > 200) {
            value = value.substring(0, 200) + "...";
        }
        return value;
    }
}

