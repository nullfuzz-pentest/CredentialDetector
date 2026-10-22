package creddetector;

import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

/** DocumentListener that runs a Runnable on any change. */
public class SimpleDocListener implements DocumentListener {
    private final Runnable action;

    public SimpleDocListener(Runnable action) {
        this.action = action;
    }

    @Override public void insertUpdate(DocumentEvent e) { action.run(); }
    @Override public void removeUpdate(DocumentEvent e) { action.run(); }
    @Override public void changedUpdate(DocumentEvent e) { action.run(); }
}
