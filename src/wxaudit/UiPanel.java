package wxaudit;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/** Swing tab shown inside Burp. All mutations are EDT-safe. */
public class UiPanel extends JPanel {

    public interface Listener {
        void onApply(String scopeText, String wxid);
        void onClearResults();
    }

    private static final String[] COLS = { "等级", "规则", "命中值", "位置", "来源 URL" };
    private static final String[] FILTERS = {
            "全部结果", "仅高危", "仅中危", "仅低危", "仅提示", "仅 secret", "仅 endpoint", "仅 pii"
    };

    private final Listener listener;
    private final List<Scanner.Finding> findings = new ArrayList<Scanner.Finding>();
    private final List<String> routes = new ArrayList<String>();
    private final DefaultTableModel tableModel = new DefaultTableModel(COLS, 0) {
        @Override public boolean isCellEditable(int row, int col) { return false; }
    };
    private JTable table;
    private JTextArea targetArea;
    private JTextField wxidField;
    private JLabel statusLabel;
    private JLabel statsLabel;
    private JComboBox<String> filterBox;
    private JTextArea detailArea;
    private JTextArea logArea;
    private int[] stats = new int[7];

    public UiPanel(Listener listener) {
        super(new BorderLayout(6, 6));
        this.listener = listener;
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        build();
    }

    private void build() {
        JPanel top = new JPanel();
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));

        JPanel scopeRow = new JPanel(new BorderLayout(4, 4));
        scopeRow.setBorder(BorderFactory.createTitledBorder("目标网址（每行一个；只扫描这些 host 的流量）"));
        targetArea = new JTextArea(3, 60);
        targetArea.setFont(new Font("Consolas", Font.PLAIN, 12));
        targetArea.setLineWrap(true);
        targetArea.setWrapStyleWord(true);
        targetArea.setToolTipText("示例:\napi.target.com\n*.target.com\nhttps://m.target.com/app/v1");
        JScrollPane scopeScroll = new JScrollPane(targetArea);
        scopeRow.add(scopeScroll, BorderLayout.CENTER);

        JPanel hint = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        hint.add(new JLabel("AppID/wxid（加密包解密用，可留空自动抓取）:"));
        wxidField = new JTextField(24);
        wxidField.setFont(new Font("Consolas", Font.PLAIN, 12));
        hint.add(wxidField);
        JButton applyBtn = new JButton("应用目标");
        applyBtn.addActionListener(new ActionListener() {
            @Override public void actionPerformed(ActionEvent e) {
                listener.onApply(targetArea.getText(), wxidField.getText());
            }
        });
        hint.add(applyBtn);
        scopeRow.add(hint, BorderLayout.SOUTH);
        top.add(scopeRow);

        JPanel statsRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        statusLabel = new JLabel("未配置目标");
        statusLabel.setFont(new Font("Dialog", Font.BOLD, 12));
        statsRow.add(statusLabel);
        top.add(statsRow);

        JPanel controlRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        statsLabel = new JLabel("扫描 0 | 跳过 0 | 发现 0 (高0 中0 低0 提示0)");
        controlRow.add(statsLabel);
        controlRow.add(new JLabel("  筛选:"));
        filterBox = new JComboBox<String>(new DefaultComboBoxModel<String>(FILTERS));
        filterBox.addActionListener(new ActionListener() {
            @Override public void actionPerformed(ActionEvent e) { refreshTable(); }
        });
        controlRow.add(filterBox);
        JButton jsonBtn = new JButton("导出 JSON");
        jsonBtn.addActionListener(new ActionListener() {
            @Override public void actionPerformed(ActionEvent e) { export(false); }
        });
        controlRow.add(jsonBtn);
        JButton htmlBtn = new JButton("导出 HTML");
        htmlBtn.addActionListener(new ActionListener() {
            @Override public void actionPerformed(ActionEvent e) { export(true); }
        });
        controlRow.add(htmlBtn);
        JButton clearBtn = new JButton("清空结果");
        clearBtn.addActionListener(new ActionListener() {
            @Override public void actionPerformed(ActionEvent e) { listener.onClearResults(); }
        });
        controlRow.add(clearBtn);
        top.add(controlRow);

        add(top, BorderLayout.NORTH);

        table = new JTable(tableModel);
        table.setFont(new Font("Consolas", Font.PLAIN, 12));
        table.setRowHeight(20);
        table.setAutoCreateRowSorter(true);
        table.getColumnModel().getColumn(0).setMaxWidth(70);
        table.getColumnModel().getColumn(1).setMaxWidth(130);
        table.getColumnModel().getColumn(3).setMaxWidth(260);
        table.getColumnModel().getColumn(4).setMaxWidth(300);
        table.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            @Override public void valueChanged(ListSelectionEvent e) { showDetail(); }
        });
        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setPreferredSize(new Dimension(900, 260));

        detailArea = new JTextArea("选中一行查看上下文与规则说明");
        detailArea.setEditable(false);
        detailArea.setLineWrap(true);
        detailArea.setFont(new Font("Consolas", Font.PLAIN, 12));
        JScrollPane detailScroll = new JScrollPane(detailArea);
        detailScroll.setBorder(BorderFactory.createTitledBorder("详情 / 可疑路由"));

        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setLineWrap(true);
        logArea.setFont(new Font("Consolas", Font.PLAIN, 11));
        JScrollPane logScroll = new JScrollPane(logArea);
        logScroll.setBorder(BorderFactory.createTitledBorder("扫描日志（跳过/解密失败会说明原因）"));

        JSplitPane bottom = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, detailScroll, logScroll);
        bottom.setResizeWeight(0.5);
        JSplitPane main = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, bottom);
        main.setResizeWeight(0.65);
        add(main, BorderLayout.CENTER);
    }

    public void setScopeText(String text) { targetArea.setText(text == null ? "" : text); }
    public void setWxidText(String text) { wxidField.setText(text == null ? "" : text); }
    public void setStatus(String text) { statusLabel.setText(text); }

    public void log(final String message) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override public void run() {
                String ts = new SimpleDateFormat("HH:mm:ss", Locale.ROOT).format(new Date());
                logArea.append("[" + ts + "] " + message + "\n");
                if (logArea.getLineCount() > 400) {
                    try { logArea.replaceRange("", 0, logArea.getLineStartOffset(logArea.getLineCount() - 300)); }
                    catch (Exception ignored) { }
                }
                logArea.setCaretPosition(logArea.getDocument().getLength());
            }
        });
    }

    public void refreshStats(final int scanned, final int skipped, final int total,
                             final int high, final int medium, final int low, final int info) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override public void run() {
                stats = new int[] { scanned, skipped, total, high, medium, low, info };
                statsLabel.setText("扫描 " + scanned + " | 跳过 " + skipped + " | 发现 " + total
                        + " (高" + high + " 中" + medium + " 低" + low + " 提示" + info + ")");
            }
        });
    }

    public void addFindings(final List<Scanner.Finding> list) {
        if (list == null || list.isEmpty()) return;
        SwingUtilities.invokeLater(new Runnable() {
            @Override public void run() {
                findings.addAll(list);
                refreshTable();
            }
        });
    }

    public void addRoutes(final List<String> newRoutes) {
        if (newRoutes == null || newRoutes.isEmpty()) return;
        SwingUtilities.invokeLater(new Runnable() {
            @Override public void run() {
                routes.addAll(newRoutes);
                showDetail();
            }
        });
    }

    private void refreshTable() {
        String filter = String.valueOf(filterBox.getSelectedItem());
        tableModel.setRowCount(0);
        for (Scanner.Finding f : findings) {
            if (!passes(f, filter)) continue;
            tableModel.addRow(new Object[] {
                    label(f.severity), f.name, f.value, f.file + ":" + f.line, f.sourceUrl
            });
        }
    }

    private static boolean passes(Scanner.Finding f, String filter) {
        if (filter.startsWith("仅")) {
            String key = filter.substring(1);
            if ("高危".equals(key)) return "high".equals(f.severity);
            if ("中危".equals(key)) return "medium".equals(f.severity);
            if ("低危".equals(key)) return "low".equals(f.severity);
            if ("提示".equals(key)) return "info".equals(f.severity);
            if ("secret".equals(key)) return "secret".equals(f.group);
            if ("endpoint".equals(key)) return "endpoint".equals(f.group);
            if ("pii".equals(key)) return "pii".equals(f.group);
        }
        return true;
    }

    private static String label(String sev) {
        if ("high".equals(sev)) return "高危";
        if ("medium".equals(sev)) return "中危";
        if ("low".equals(sev)) return "低危";
        return "提示";
    }

    private void showDetail() {
        int row = table.getSelectedRow();
        StringBuilder sb = new StringBuilder();
        if (row >= 0) {
            int modelRow = table.convertRowIndexToModel(row);
            if (modelRow >= 0 && modelRow < findings.size()) {
                // table may be filtered; locate via displayed value instead of index
                String val = String.valueOf(tableModel.getValueAt(modelRow, 2));
                for (Scanner.Finding f : findings) {
                    if (f.value.equals(val)) {
                        sb.append("规则: ").append(f.rule).append(" / ").append(f.name).append("\n");
                        sb.append("等级: ").append(label(f.severity)).append("   分类: ").append(f.group).append("\n");
                        sb.append("命中值: ").append(f.value).append("\n");
                        sb.append("位置: ").append(f.file).append(":").append(f.line).append("\n");
                        sb.append("来源: ").append(f.sourceUrl).append("\n\n");
                        sb.append("上下文:\n").append(f.snippet).append("\n");
                        if (!f.note.isEmpty()) sb.append("\n说明: ").append(f.note).append("\n");
                        break;
                    }
                }
            }
        }
        if (!routes.isEmpty()) {
            sb.append("\n可疑路由（app-config.json）:\n");
            for (String r : routes) sb.append("  ! ").append(r).append("\n");
        }
        if (sb.length() == 0) sb.append("选中一行查看上下文与规则说明");
        detailArea.setText(sb.toString());
    }

    private void export(boolean html) {
        if (findings.isEmpty()) {
            JOptionPane.showMessageDialog(this, "当前没有扫描结果可导出", "wxaudit", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("导出扫描结果");
        fc.setSelectedFile(new File("wxaudit-report-" + new SimpleDateFormat("yyyyMMdd-HHmmss").format(new Date())
                + (html ? ".html" : ".json")));
        if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
        try {
            if (html) Exporter.writeHtml(fc.getSelectedFile(), findings, statusLabel.getText(), stats);
            else Exporter.writeJson(fc.getSelectedFile(), findings, statusLabel.getText(), stats);
            log("报告已导出: " + fc.getSelectedFile().getAbsolutePath());
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "导出失败: " + ex.getMessage(), "wxaudit", JOptionPane.ERROR_MESSAGE);
        }
    }
}
