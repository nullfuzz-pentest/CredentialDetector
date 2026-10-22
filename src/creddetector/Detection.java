package creddetector;

import burp.api.montoya.http.message.HttpRequestResponse;

/** Represents a detection (a table row). */
public class Detection {
    public final String timestamp;
    public final String method;
    public final String url;
    public final String host;
    public final String terms;
    public final int count;
    public final HttpRequestResponse requestResponse;
    /** Full response text, for the viewer with highlighting. */
    public final String responseText;
    /** Detailed findings: each with the term, value and context. */
    public final java.util.List<Finding> findings;

    public Detection(String timestamp, String method, String url, String host,
                     String terms, int count, HttpRequestResponse requestResponse,
                     String responseText, java.util.List<Finding> findings) {
        this.timestamp = timestamp;
        this.method = method;
        this.url = url;
        this.host = host;
        this.terms = terms;
        this.count = count;
        this.requestResponse = requestResponse;
        this.responseText = responseText;
        this.findings = findings;
    }

    /** A single finding within the response. */
    public static class Finding {
        public final String term;    // detected keyword (e.g. access_key)
        public final String value;   // associated value (e.g. AKIAFAKE...), if detected
        public final String context; // line/fragment where it appears

        public Finding(String term, String value, String context) {
            this.term = term;
            this.value = value;
            this.context = context;
        }
    }
}
