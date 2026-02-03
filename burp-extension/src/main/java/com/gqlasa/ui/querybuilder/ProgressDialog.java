package com.gqlasa.ui.querybuilder;

import javax.swing.*;
import java.awt.*;

public class ProgressDialog {
    private final JDialog dialog;
    private final JLabel title;
    private final JLabel anim;
    private final JProgressBar bar;
    private final Timer timer;

    private long startMs = 0L;
    private long finishMs = -1L;
    private volatile boolean finishing = false;

    // Larger -> slower growth; smaller -> faster growth.
    private static final double TAU_MS = 2500.0;

    public ProgressDialog(Window owner, String text) {
        dialog = new JDialog(owner, "Please wait", Dialog.ModalityType.MODELESS);
        dialog.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
        dialog.setResizable(false);

        title = new JLabel(text);
        title.setFont(title.getFont().deriveFont(Font.BOLD, 13f));

        anim = new JLabel(" ");
        anim.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        bar = new JProgressBar(0, 100);
        bar.setIndeterminate(false);
        bar.setValue(0);
        bar.setStringPainted(true);
        bar.setString("0%");

        JPanel p = new JPanel(new BorderLayout(8, 8));
        p.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        p.add(title, BorderLayout.NORTH);
        p.add(bar, BorderLayout.CENTER);
        p.add(anim, BorderLayout.SOUTH);

        dialog.setContentPane(p);
        dialog.pack();
        dialog.setSize(new Dimension(380, dialog.getHeight()));
        dialog.setLocationRelativeTo(owner);

        timer = new Timer(80, e -> tick());
        timer.setInitialDelay(0);
    }

    public void showDialog() {
        startMs = System.currentTimeMillis();
        finishMs = -1L;
        finishing = false;

        bar.setValue(0);
        bar.setString("0%");
        anim.setText(" ");

        dialog.setVisible(true);
        timer.start();
        tick();
    }

    public void complete(String finalText) {
        SwingUtilities.invokeLater(() -> {
            title.setText(finalText);
            finishing = true;
            if (finishMs < 0) finishMs = System.currentTimeMillis();
        });
    }

    private void tick() {
        long now = System.currentTimeMillis();
        int pct;

        if (!finishing) {
            long elapsed = Math.max(0, now - startMs);

            // Smooth rise toward 95%: p = 95 * (1 - exp(-t/tau))
            double p = 95.0 * (1.0 - Math.exp(-(elapsed / TAU_MS)));
            pct = (int) Math.max(1, Math.min(95, Math.round(p)));
        } else {
            // Animate remaining 5% over ~1.2 seconds
            long sinceFinish = Math.max(0, now - finishMs);
            double t = Math.min(1.0, sinceFinish / 1200.0);
            int current = bar.getValue();

            // Smoothstep
            double s = t * t * (3 - 2 * t);
            pct = (int) Math.round(current + (100 - current) * s);
            pct = Math.max(current, Math.min(100, pct));
        }

        bar.setValue(pct);
        bar.setString(pct + "%");

        int blocks = Math.max(1, (pct / 10));
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < blocks; i++) sb.append("■");
        anim.setText(sb.toString());

        if (finishing && pct >= 100) {
            timer.stop();
            new Timer(250, e -> dialog.dispose()).start();
        }
    }
}
