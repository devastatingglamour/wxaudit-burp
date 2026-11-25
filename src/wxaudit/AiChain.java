package wxaudit;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * AI 完整利用链结论（仅授权测试）/ AI full exploit chain (authorized testing only).
 */
public final class AiChain {
    public final String vulnType;           // 漏洞类型
    public final List<String> preconditions; // 前置条件
    public final List<String> steps;         // 有序测试步骤
    public final String expectedResult;      // 预期结果
    public final String riskLevel;           // critical/high/medium/low/none/unknown
    public final String summary;

    public AiChain(String vulnType, List<String> preconditions, List<String> steps,
                   String expectedResult, String riskLevel, String summary) {
        this.vulnType = vulnType == null ? "unknown" : vulnType;
        this.preconditions = copy(preconditions);
        this.steps = copy(steps);
        this.expectedResult = expectedResult == null ? "" : expectedResult;
        this.riskLevel = riskLevel == null ? "unknown" : riskLevel;
        this.summary = summary == null ? "" : summary;
    }

    private static List<String> copy(List<String> in) {
        return in == null ? Collections.<String>emptyList()
                : Collections.unmodifiableList(new ArrayList<String>(in));
    }
}
