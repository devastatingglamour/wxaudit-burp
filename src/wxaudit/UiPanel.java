package wxaudit;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
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
        // Java 8 default methods: legacy anonymous implementations stay source-compatible.
        default void onAiConfigApply(AiConfig cfg) { }
        default void onAnalyzeSelected(List<String> packetIds) { }
    }

    private static final String[] COLS = { "时间", "等级", "规则", "命中值", "位置", "来源 URL" };
    private static final String[] PACKET_COLS = { "时间", "方法", "URL", "发现数", "最高等级", "类型" };
    private static final String[] FILTERS = {
            "全部结果", "仅高危", "仅中危", "仅低危", "仅提示", "仅 secret", "仅 endpoint", "仅 pii"
    };
    private static final SimpleDateFormat TIME_FMT = new SimpleDateFormat("HH:mm:ss", Locale.ROOT);

    private final Listener listener;
    private final List<Scanner.Finding> findings = new ArrayList<Scanner.Finding>();
    private final List<Scanner.Finding> visibleFindings = new ArrayList<Scanner.Finding>();
    private final List<RouteFinding> routes = new ArrayList<RouteFinding>();
    private final List<CapturedPacket> packets = new ArrayList<CapturedPacket>();
    private final DefaultTableModel tableModel = new DefaultTableModel(COLS, 0) {
        @Override public boolean isCellEditable(int row, int col) { return false; }
    };
    private final DefaultTableModel packetModel = new DefaultTableModel(PACKET_COLS, 0) {
        @Override public boolean isCellEditable(int row, int col) { return false; }
    };
    private JTable table;
    private JTable packetTable;
    private JTextArea targetArea;
    private JTextField wxidField;
    private JLabel statusLabel;
    private JLabel statsLabel;
    private JLabel aiStatsLabel;
    private JComboBox<String> filterBox;
    private JTextArea detailArea;
    private JTextArea logArea;
    // AI config widgets
    private JCheckBox aiEnableBox;
    private JTextField aiBaseUrlField;
    private JPasswordField aiKeyField;
    private JTextField aiModelField;
    private JTextField aiTimeoutField;
    private JTextField aiBatchField;
    private JTextField aiTokensField;
    private JCheckBox aiRealtimeBox;
    private JCheckBox aiChainBox;
    private int[] stats = new int[7];
    private AiResultStore aiResultStore = null;

    public UiPanel(Listener listener) {
        super(new BorderLayout(6, 6));
        this.listener = listener;
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        build();
    }

    private void build() {
        JPanel top = new JPanel();
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));

        // ---- scope row ----
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

        // ---- AI config rows (default OFF) ----
        JPanel aiRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        aiRow.setBorder(BorderFactory.createTitledBorder("AI 增强（可选，默认关闭；仅用于自有/授权目标）"));
        aiEnableBox = new JCheckBox("启用 AI 分析");
        aiEnableBox.setToolTipText("未勾选时不发送任何网络请求");
        aiRow.add(aiEnableBox);
        aiRow.add(new JLabel("base_url:"));
        aiBaseUrlField = new JTextField("https://api.openai.com/v1", 22);
        aiBaseUrlField.setFont(new Font("Consolas", Font.PLAIN, 11));
        aiRow.add(aiBaseUrlField);
        aiRow.add(new JLabel("模型:"));
        aiModelField = new JTextField("gpt-4o-mini", 14);
        aiModelField.setFont(new Font("Consolas", Font.PLAIN, 11));
        aiRow.add(aiModelField);
        aiRow.add(new JLabel("API Key:"));
        aiKeyField = new JPasswordField(18);
        aiRow.add(aiKeyField);
        top.add(aiRow);

        JPanel aiRow2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        aiRow2.add(new JLabel("超时ms:"));
        aiTimeoutField = new JTextField("30000", 6);
        aiRow2.add(aiTimeoutField);
        aiRow2.add(new JLabel("每批:"));
        aiBatchField = new JTextField("10", 4);
        aiRow2.add(aiBatchField);
        aiRow2.add(new JLabel("max_tokens:"));
        aiTokensField = new JTextField("2000", 6);
        aiRow2.add(aiTokensField);
        aiRealtimeBox = new JCheckBox("实时逐条（增加费用）");
        aiRealtimeBox.setToolTipText("关闭时只在“数据包”视图手动选择后分析");
        aiRow2.add(aiRealtimeBox);
        aiChainBox = new JCheckBox("生成利用链");
        aiChainBox.setSelected(true);
        aiRow2.add(aiChainBox);
        JButton saveAiBtn = new JButton("保存 AI 配置");
        saveAiBtn.addActionListener(new ActionListener() {
            @Override public void actionPerformed(ActionEvent e) { applyAiConfig(); }
        });
        aiRow2.add(saveAiBtn);
        JButton analyzeBtn = new JButton("AI 分析选中包");
        analyzeBtn.setToolTipText("请在“数据包”视图选择一个或多个包后点击");
        analyzeBtn.addActionListener(new ActionListener() {
            @Override public void actionPerformed(ActionEvent e) {
                int[] rows = packetTable.getSelectedRows();
                List<String> ids = new ArrayList<String>();
                for (int row : rows) {
                    int modelRow = packetTable.convertRowIndexToModel(row);
                    if (modelRow >= 0 && modelRow < packets.size()) ids.add(packets.get(modelRow).id);
                }
                if (ids.isEmpty()) {
                    JOptionPane.showMessageDialog(UiPanel.this,
                            "请先在“数据包”视图选择一个或多个数据包", "wxaudit", JOptionPane.INFORMATION_MESSAGE);
                    return;
                }
                listener.onAnalyzeSelected(ids);
            }
        });
        aiRow2.add(analyzeBtn);
        top.add(aiRow2);

        JPanel statsRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        statusLabel = new JLabel("未配置目标");
        statusLabel.setFont(new Font("Dialog", Font.BOLD, 12));
        statsRow.add(statusLabel);
        top.add(statsRow);

        JPanel controlRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        statsLabel = new JLabel("扫描 0 | 跳过 0 | 发现 0");
        controlRow.add(statsLabel);
        aiStatsLabel = new JLabel("AI 0/0");
        controlRow.add(aiStatsLabel);
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

        // ---- tables in a tabbed pane ----
        table = new JTable(tableModel);
        table.setFont(new Font("Consolas", Font.PLAIN, 12));
        table.setRowHeight(20);
        table.setAutoCreateRowSorter(true);
        table.getColumnModel().getColumn(0).setMaxWidth(80);
        table.getColumnModel().getColumn(1).setMaxWidth(60);
        table.getColumnModel().getColumn(2).setMaxWidth(130);
        table.getColumnModel().getColumn(4).setMaxWidth(220);
        table.getColumnModel().getColumn(5).setMaxWidth(280);
        table.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            @Override public void valueChanged(ListSelectionEvent e) { if (!e.getValueIsAdjusting()) showDetail(); }
        });
        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setPreferredSize(new Dimension(900, 220));

        packetTable = new JTable(packetModel);
        packetTable.setFont(new Font("Consolas", Font.PLAIN, 12));
        packetTable.setRowHeight(20);
        packetTable.setAutoCreateRowSorter(true);
        packetTable.setSelectionMode(javax.swing.ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        packetTable.getColumnModel().getColumn(0).setMaxWidth(80);
        packetTable.getColumnModel().getColumn(1).setMaxWidth(70);
        packetTable.getColumnModel().getColumn(3).setMaxWidth(70);
        packetTable.getColumnModel().getColumn(4).setMaxWidth(80);
        packetTable.getColumnModel().getColumn(5).setMaxWidth(110);
        packetTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            @Override public void valueChanged(ListSelectionEvent e) { if (!e.getValueIsAdjusting()) showPacketDetail(); }
        });
        JScrollPane packetScroll = new JScrollPane(packetTable);
        packetScroll.setPreferredSize(new Dimension(900, 220));

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("扫描结果", tableScroll);
        tabs.addTab("数据包（选包做 AI 分析）", packetScroll);

        detailArea = new JTextArea("选中一行查看上下文与规则说明");
        detailArea.setEditable(false);
        detailArea.setLineWrap(true);
        detailArea.setFont(new Font("Consolas", Font.PLAIN, 12));
        JScrollPane detailScroll = new JScrollPane(detailArea);
        detailScroll.setBorder(BorderFactory.createTitledBorder("详情 / AI 研判 / 利用链 / 可疑路由"));

        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setLineWrap(true);
        logArea.setFont(new Font("Consolas", Font.PLAIN, 11));
        JScrollPane logScroll = new JScrollPane(logArea);
        logScroll.setBorder(BorderFactory.createTitledBorder("扫描日志（跳过/解密失败会说明原因）"));

        JSplitPane bottom = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, detailScroll, logScroll);
        bottom.setResizeWeight(0.5);
        JSplitPane main = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tabs, bottom);
        main.setResizeWeight(0.65);
        add(main, BorderLayout.CENTER);
    }

    // ------------------------------------------------------------------
    private void applyAiConfig() {
        AiConfig cfg = new AiConfig(
                aiEnableBox.isSelected(),
                aiBaseUrlField.getText(),
                new String(aiKeyField.getPassword()),
                aiModelField.getText(),
                parseInt(aiTimeoutField.getText(), 30000),
                parseInt(aiBatchField.getText(), 10),
                parseInt(aiTokensField.getText(), 2000),
                aiRealtimeBox.isSelected(),
                aiChainBox.isSelected(),
                0
        );
        String err = cfg.validate();
        if (err != null) {
            JOptionPane.showMessageDialog(this, err, "AI 配置", JOptionPane.WARNING_MESSAGE);
            return;
        }
        listener.onAiConfigApply(cfg);
    }

    private static int parseInt(String s, int def) {
        try { return Integer.parseInt(s == null ? "" : s.trim()); }
        catch (NumberFormatException ex) { return def; }
    }

    public void setAiConfig(AiConfig c) {
        if (c == null) c = AiConfig.defaults();
        aiEnableBox.setSelected(c.enabled);
        aiBaseUrlField.setText(c.baseUrl);
        aiKeyField.setText(c.apiKey);
        aiModelField.setText(c.model);
        aiTimeoutField.setText(String.valueOf(c.timeoutMs));
        aiBatchField.setText(String.valueOf(c.maxBatch));
        aiTokensField.setText(String.valueOf(c.maxTokens));
        aiRealtimeBox.setSelected(c.realtime);
        aiChainBox.setSelected(c.exploitChain);
    }

    public void setScopeText(String text) { targetArea.setText(text == null ? "" : text); }
    public void setWxidText(String text) { wxidField.setText(text == null ? "" : text); }
    public void setStatus(String text) { statusLabel.setText(text); }

    public void log(final String message) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override public void run() {
                String ts = TIME_FMT.format(new Date());
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

    public void setAiStats(final int analyzed, final int packetsCount, final int falsePositives) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override public void run() {
                aiStatsLabel.setText("AI " + analyzed + "/" + packetsCount + " 包, 误报 " + falsePositives);
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

    public void addPacket(final CapturedPacket p) {
        if (p == null) return;
        SwingUtilities.invokeLater(new Runnable() {
            @Override public void run() {
                packets.add(p);
                refreshPacketTable();
                if (packets.size() > 2000 && !packets.isEmpty()) packets.remove(0);
            }
        });
    }

    public void addRoutes(final List<RouteFinding> newRoutes) {
        if (newRoutes == null || newRoutes.isEmpty()) return;
        SwingUtilities.invokeLater(new Runnable() {
            @Override public void run() {
                routes.addAll(newRoutes);
                showDetail();
            }
        });
    }

    /** Legacy string overload for compatibility. */
    public void addRoutes(final List<String> ignored, boolean legacy) { }

    public void clearAll() {
        SwingUtilities.invokeLater(new Runnable() {
            @Override public void run() {
                findings.clear();
                visibleFindings.clear();
                packets.clear();
                routes.clear();
                if (aiResultStore != null) aiResultStore.clear();
                tableModel.setRowCount(0);
                packetModel.setRowCount(0);
                detailArea.setText("选中一行查看上下文与规则说明");
                aiStatsLabel.setText("AI 0/0");
            }
        });
    }

    public void setAiResults(AiResultStore store) {
        this.aiResultStore = store;
        SwingUtilities.invokeLater(new Runnable() {
            @Override public void run() { refreshPacketTable(); showDetail(); }
        });
    }

    List<RouteFinding> routesSnapshot() {
        return new ArrayList<RouteFinding>(routes);
    }

    // ------------------------------------------------------------------
    private void refreshPacketTable() {
        packetModel.setRowCount(0);
        for (CapturedPacket p : packets) {
            int count = p.findingKeys.size();
            String maxSev = "";
            packetModel.addRow(new Object[] {
                    TIME_FMT.format(new Date(p.timestamp)), p.method,
                    p.sourceUrl, count, maxSev, p.kind
            });
        }
    }

    private void refreshTable() {
        String filter = String.valueOf(filterBox.getSelectedItem());
        tableModel.setRowCount(0);
        visibleFindings.clear();
        for (Scanner.Finding f : findings) {
            if (!passes(f, filter)) continue;
            visibleFindings.add(f);
            tableModel.addRow(new Object[] {
                    TIME_FMT.format(new Date(f.timestamp)), label(f.severity), f.name,
                    f.value, f.file + ":" + f.line, f.sourceUrl
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
            if (modelRow >= 0 && modelRow < visibleFindings.size()) {
                Scanner.Finding f = visibleFindings.get(modelRow);
                sb.append("规则: ").append(f.rule).append(" / ").append(f.name).append("\n");
                sb.append("等级: ").append(label(f.severity)).append("   分类: ").append(f.group).append("\n");
                sb.append("命中值: ").append(f.value).append("\n");
                sb.append("位置: ").append(f.file).append(":").append(f.line).append("\n");
                sb.append("来源: ").append(f.sourceUrl).append("\n\n");
                sb.append("上下文:\n").append(f.snippet).append("\n");
                if (!f.note.isEmpty()) sb.append("\n说明: ").append(f.note).append("\n");
            }
        }
        if (!routes.isEmpty()) {
            sb.append("\n可疑路由（app-config.json）:\n");
            for (RouteFinding r : routes) {
                sb.append("  ! ").append(r.route).append("  @ ").append(r.file)
                        .append(":").append(r.line).append("\n");
            }
        }
        if (sb.length() == 0) sb.append("选中一行查看上下文与规则说明");
        detailArea.setText(sb.toString());
    }

    private void showPacketDetail() {
        int row = packetTable.getSelectedRow();
        StringBuilder sb = new StringBuilder();
        if (row >= 0) {
            int modelRow = packetTable.convertRowIndexToModel(row);
            if (modelRow >= 0 && modelRow < packets.size()) {
                CapturedPacket p = packets.get(modelRow);
                sb.append("数据包: ").append(p.method).append(" ").append(p.sourceUrl).append("\n");
                sb.append("类型: ").append(p.kind).append("   命中: ").append(p.findingKeys.size()).append("\n\n");
                sb.append("请求头（脱敏）:\n").append(p.requestHead).append("\n\n");
                sb.append("响应摘要（脱敏）:\n").append(p.responseExcerpt).append("\n");
                AiResult ar = aiResultStore == null ? null : aiResultStore.get(p.id);
                if (ar != null) appendAiResult(sb, ar);
            }
        }
        if (sb.length() == 0) sb.append("选中一个数据包查看详情；多选后点“AI 分析选中包”");
        detailArea.setText(sb.toString());
    }

    private static void appendAiResult(StringBuilder sb, AiResult ar) {
        sb.append("\n===== AI 分析 (");
        sb.append(ar.ok() ? "成功" : "失败").append(") =====\n");
        if (!ar.error.isEmpty()) {
            sb.append("错误: ").append(ar.error).append("\n");
            return;
        }
        if (ar.triage != null) {
            sb.append("[误报研判] 结论=").append(ar.triage.overallVerdict)
                    .append(" 置信度=").append(ar.triage.confidence).append("\n");
            sb.append("理由: ").append(ar.triage.reason).append("\n");
        }
        if (ar.chain != null) {
            sb.append("[利用链] 漏洞类型=").append(ar.chain.vulnType)
                    .append(" 风险=").append(ar.chain.riskLevel).append("\n");
            if (!ar.chain.preconditions.isEmpty()) {
                sb.append("前置条件:\n");
                for (String s : ar.chain.preconditions) sb.append("  - ").append(s).append("\n");
            }
            if (!ar.chain.steps.isEmpty()) {
                sb.append("测试步骤:\n");
                for (int i = 0; i < ar.chain.steps.size(); i++)
                    sb.append("  ").append(i + 1).append(". ").append(ar.chain.steps.get(i)).append("\n");
            }
            sb.append("预期结果: ").append(ar.chain.expectedResult).append("\n");
            sb.append("摘要: ").append(ar.chain.summary).append("\n");
        }
        sb.append("（AI 输出仅供参考，需人工复核；仅用于自有或已授权目标）\n");
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
            List<AiResult> aiList = aiResultStore == null ? new ArrayList<AiResult>() : aiResultStore.all();
            if (html) Exporter.writeHtml(fc.getSelectedFile(), findings, statusLabel.getText(), stats, routes, aiList);
            else Exporter.writeJson(fc.getSelectedFile(), findings, statusLabel.getText(), stats, routes, aiList);
            log("报告已导出: " + fc.getSelectedFile().getAbsolutePath());
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "导出失败: " + ex.getMessage(), "wxaudit", JOptionPane.ERROR_MESSAGE);
        }
    }
}
