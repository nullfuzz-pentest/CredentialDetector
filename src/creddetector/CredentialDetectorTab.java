package creddetector;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.HttpRequestEditor;

import javax.swing.*;
import javax.swing.table.TableRowSorter;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.api.montoya.ui.editor.EditorOptions.READ_ONLY;

/** Extension tab: detections table + viewers with highlighting. */
public class CredentialDetectorTab {

    private final MontoyaApi api;
    private final DetectionTableModel model;
    private final JTable table;
    private final TableRowSorter<DetectionTableModel> sorter;
    private final JTextField filterField;
    private final JLabel countLabel;
    private final JLabel seenLabel;
    private final HttpRequestEditor requestEditor;
    private final JTextPane responsePane;
    private final JPanel panel;
    private final JPopupMenu popup;

    public CredentialDetectorTab(MontoyaApi api) {
        this.api = api;
        this.model = new DetectionTableModel();

        this.table = new JTable(model);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        this.sorter = new TableRowSorter<>(model);
        table.setRowSorter(sorter);
        table.getColumnModel().getColumn(0).setPreferredWidth(35);
        table.getColumnModel().getColumn(1).setPreferredWidth(90);
        table.getColumnModel().getColumn(2).setPreferredWidth(60);
        table.getColumnModel().getColumn(3).setPreferredWidth(160);
        table.getColumnModel().getColumn(4).setPreferredWidth(320);
        table.getColumnModel().getColumn(5).setPreferredWidth(90);
        table.getColumnModel().getColumn(6).setPreferredWidth(300);

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showRow(table.getSelectedRow());
            }
        });

        this.popup = buildContextMenu();
        table.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent ev) { maybeShow(ev); }
            @Override public void mouseReleased(MouseEvent ev) { maybeShow(ev); }
            private void maybeShow(MouseEvent ev) {
                if (ev.isPopupTrigger()) {
                    int row = table.rowAtPoint(ev.getPoint());
                    if (row >= 0) {
                        table.setRowSelectionInterval(row, row);
                    }
                    popup.show(ev.getComponent(), ev.getX(), ev.getY());
                }
            }
        });

        JScrollPane tableScroll = new JScrollPane(table);

        // Request: editor nativo de Burp (Pretty/Raw/Hex).
        this.requestEditor = api.userInterface().createHttpRequestEditor(READ_ONLY);

        // Response: custom viewer with guaranteed highlighting of ALL terms
        // (black text on yellow), independent of the editor.
        this.responsePane = new JTextPane();
        responsePane.setEditable(false);
        responsePane.setFont(new Font("Monospaced", Font.PLAIN, 12));
        responsePane.setBackground(new Color(43, 43, 43));
        responsePane.setForeground(new Color(220, 220, 220));
        responsePane.setCaretColor(new Color(220, 220, 220));
        JScrollPane responseScroll = new JScrollPane(responsePane);

        JTabbedPane viewers = new JTabbedPane();
        viewers.addTab("Request", requestEditor.uiComponent());
        viewers.addTab("Response", responseScroll);

        // Top bar: counters + filter + export + clear.
        JToolBar toolbar = new JToolBar();
        toolbar.setFloatable(false);
        this.countLabel = new JLabel("Detections: 0   ");
        this.seenLabel = new JLabel("HTTP seen: 0   ");
        this.filterField = new JTextField(20);
        filterField.getDocument().addDocumentListener(new SimpleDocListener(this::applyFilter));
        JButton clearFilter = new JButton("x");
        clearFilter.setToolTipText("Clear filter");
        clearFilter.addActionListener(e -> { filterField.setText(""); applyFilter(); });
        JButton exportButton = new JButton("Export CSV");
        exportButton.addActionListener(e -> exportCsv());
        JButton clearButton = new JButton("Clear");
        clearButton.addActionListener(e -> onClear());

        toolbar.add(countLabel);
        toolbar.add(seenLabel);
        toolbar.addSeparator();
        toolbar.add(new JLabel("Search: "));
        toolbar.add(filterField);
        toolbar.add(clearFilter);
        toolbar.addSeparator();
        toolbar.add(exportButton);
        toolbar.add(clearButton);

        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(toolbar, BorderLayout.NORTH);
        topPanel.add(tableScroll, BorderLayout.CENTER);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        split.setTopComponent(topPanel);
        split.setBottomComponent(viewers);
        split.setResizeWeight(0.5);
        split.setDividerLocation(280);

        this.panel = new JPanel(new BorderLayout());
        panel.add(split, BorderLayout.CENTER);
    }

    public Component getUiComponent() {
        return panel;
    }

    // ------------------------------------------------------------------
    // API used by the handler
    // ------------------------------------------------------------------
    public void addDetection(Detection detection) {
        SwingUtilities.invokeLater(() -> {
            model.addDetection(detection);
            updateCountLabel();
        });
    }

    public void bumpSeen(int total) {
        SwingUtilities.invokeLater(() -> seenLabel.setText("HTTP seen: " + total + "   "));
    }

    // ------------------------------------------------------------------
    // Row selection -> shows request/response and HIGHLIGHTS the matches
    // ------------------------------------------------------------------
    private void showRow(int viewRow) {
        if (viewRow < 0) {
            return;
        }
        int modelRow = table.convertRowIndexToModel(viewRow);
        Detection d = model.getDetection(modelRow);
        if (d == null) {
            return;
        }
        if (d.requestResponse.request() != null) {
            requestEditor.setRequest(d.requestResponse.request());
        }
        renderResponse(d);
    }

    /**
     * Shows the response in the custom viewer and highlights ALL terms
     * (black text on yellow). Recomputes the matches over the text already
     * normalized to '\n' so the highlight offsets match the JTextPane
     * document.
     */
    private void renderResponse(Detection d) {
        String raw = (d.responseText != null) ? d.responseText : "";
        String text = raw.replace("\r\n", "\n").replace("\r", "\n");

        responsePane.setText(text);
        responsePane.setCaretPosition(0);

        StyledDocument doc = responsePane.getStyledDocument();

        SimpleAttributeSet normal = new SimpleAttributeSet();
        StyleConstants.setForeground(normal, new Color(220, 220, 220));
        doc.setCharacterAttributes(0, doc.getLength(), normal, true);

        SimpleAttributeSet hit = new SimpleAttributeSet();
        StyleConstants.setBackground(hit, new Color(255, 214, 0));
        StyleConstants.setForeground(hit, new Color(0, 0, 0));
        StyleConstants.setBold(hit, true);

        Matcher matcher = CredentialRegex.PATTERN.matcher(text);
        int firstStart = -1;
        while (matcher.find()) {
            int start = matcher.start();
            int termEnd = matcher.end();
            // Highlight extends from the keyword up to the end of its value,
            // so the full detected value is marked (e.g. api_key = sk_test_...).
            int valueEnd = valueEndIndex(text, termEnd);
            int length = valueEnd - start;
            doc.setCharacterAttributes(start, length, hit, false);
            if (firstStart < 0) {
                firstStart = start;
            }
        }
        if (firstStart >= 0) {
            responsePane.setCaretPosition(firstStart);
        }
    }

    /**
     * Given the position right after a detected keyword, returns the index in
     * {@code text} where the associated value ends. Skips the typical
     * separators (= : " ' > space) and then consumes the value until the end
     * of line or a closing delimiter. Mirrors the extraction logic used by the
     * HTTP handler so the highlight covers the full value.
     */
    private static int valueEndIndex(String text, int termEnd) {
        int i = termEnd;
        int n = text.length();
        // Skip spaces and common separators (= : " ' > space, nbsp).
        while (i < n) {
            char c = text.charAt(i);
            if (c == ' ' || c == '\t' || c == '=' || c == ':' || c == '"'
                || c == '\'' || c == '>' || c == '\u00a0') {
                i++;
            } else {
                break;
            }
        }
        // Consume the value until end of line or a closing delimiter.
        while (i < n) {
            char c = text.charAt(i);
            if (c == '\n' || c == '"' || c == '\'' || c == '<'
                || c == ',' || c == ';' || c == '}') {
                break;
            }
            i++;
        }
        return i;
    }

    private void onClear() {
        model.clear();
        updateCountLabel();
    }

    // ------------------------------------------------------------------
    // Search filter over the table (host, URL, terms)
    // ------------------------------------------------------------------
    private void applyFilter() {
        String text = filterField.getText();
        if (text == null || text.trim().isEmpty()) {
            sorter.setRowFilter(null);
        } else {
            String regex = "(?i)" + Pattern.quote(text);
            sorter.setRowFilter(RowFilter.regexFilter(regex, 3, 4, 6));
        }
        updateCountLabel();
    }

    private void updateCountLabel() {
        int total = model.count();
        int visible = table.getRowCount();
        if (visible == total) {
            countLabel.setText("Detections: " + total + "   ");
        } else {
            countLabel.setText("Detections: " + visible + " of " + total + "   ");
        }
    }

    // ------------------------------------------------------------------
    // Context menu
    // ------------------------------------------------------------------
    private JPopupMenu buildContextMenu() {
        JPopupMenu menu = new JPopupMenu();
        JMenuItem toRepeater = new JMenuItem("Send to Repeater");
        toRepeater.addActionListener(e -> {
            Detection d = selectedDetection();
            if (d != null && d.requestResponse.request() != null) {
                api.repeater().sendToRepeater(d.requestResponse.request(), "CredDetector");
            }
        });
        JMenuItem toIntruder = new JMenuItem("Send to Intruder");
        toIntruder.addActionListener(e -> {
            Detection d = selectedDetection();
            if (d != null && d.requestResponse.request() != null) {
                api.intruder().sendToIntruder(d.requestResponse.request());
            }
        });
        JMenuItem copyUrl = new JMenuItem("Copy URL");
        copyUrl.addActionListener(e -> {
            Detection d = selectedDetection();
            if (d != null) {
                Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(d.url), null);
            }
        });
        JMenuItem exportItem = new JMenuItem("Export CSV...");
        exportItem.addActionListener(e -> exportCsv());

        menu.add(toRepeater);
        menu.add(toIntruder);
        menu.addSeparator();
        menu.add(copyUrl);
        menu.addSeparator();
        menu.add(exportItem);
        return menu;
    }

    private Detection selectedDetection() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            return null;
        }
        int modelRow = table.convertRowIndexToModel(viewRow);
        return model.getDetection(modelRow);
    }

    // ------------------------------------------------------------------
    // Export to CSV
    // ------------------------------------------------------------------
    private String csvEscape(Object value) {
        String text = (value == null) ? "" : value.toString();
        text = text.replace("\"", "\"\"");
        return "\"" + text + "\"";
    }

    private void exportCsv() {
        if (model.count() == 0) {
            JOptionPane.showMessageDialog(panel, "No detections to export.");
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("credential_detections.csv"));
        if (chooser.showSaveDialog(panel) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        File path = chooser.getSelectedFile();
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(path))) {
            // One row per detected credential, with all the data.
            String[] headers = {"Detection#", "Time", "Method", "Host", "URL",
                                "Term", "Value", "Context"};
            StringBuilder head = new StringBuilder();
            for (int i = 0; i < headers.length; i++) {
                if (i > 0) head.append(",");
                head.append(csvEscape(headers[i]));
            }
            writer.write(head.toString());
            writer.write("\n");

            int detIndex = 1;
            int rowsWritten = 0;
            for (Detection d : model.getRows()) {
                if (d.findings != null && !d.findings.isEmpty()) {
                    for (Detection.Finding f : d.findings) {
                        writeCsvRow(writer, detIndex, d, f.term, f.value, f.context);
                        rowsWritten++;
                    }
                } else {
                    // Fallback: at least the row with the aggregated terms.
                    writeCsvRow(writer, detIndex, d, d.terms, "", "");
                    rowsWritten++;
                }
                detIndex++;
            }
            writer.flush();
            JOptionPane.showMessageDialog(panel,
                "Exported " + rowsWritten + " credentials ("
                + model.count() + " detections) to:\n" + path.getAbsolutePath());
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(panel, "Error exporting CSV: " + ex.getMessage());
        }
    }

    private void writeCsvRow(BufferedWriter writer, int detIndex, Detection d,
                             String term, String value, String context)
            throws java.io.IOException {
        String line = csvEscape(detIndex) + "," + csvEscape(d.timestamp) + ","
            + csvEscape(d.method) + "," + csvEscape(d.host) + ","
            + csvEscape(d.url) + "," + csvEscape(term) + ","
            + csvEscape(value) + "," + csvEscape(context);
        writer.write(line);
        writer.write("\n");
    }
}
