package wxaudit;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * AI 误报研判结论 / AI false-positive triage verdict.
 */
public final class AiTriage {
    /** true_positive / false_positive / mixed / uncertain / unknown */
    public final String overallVerdict;
    public final int confidence;         // 0-100
    public final String reason;
    public final List<FindingVerdict> perFinding;

    public static final class FindingVerdict {
        public final String findingKey;
        public final String verdict;
        public final String reason;

        public FindingVerdict(String findingKey, String verdict, String reason) {
            this.findingKey = findingKey == null ? "" : findingKey;
            this.verdict = verdict == null ? "unknown" : verdict;
            this.reason = reason == null ? "" : reason;
        }
    }

    public AiTriage(String overallVerdict, int confidence, String reason,
                    List<FindingVerdict> perFinding) {
        this.overallVerdict = overallVerdict == null ? "unknown" : overallVerdict;
        this.confidence = confidence;
        this.reason = reason == null ? "" : reason;
        this.perFinding = perFinding == null
                ? Collections.<FindingVerdict>emptyList()
                : Collections.unmodifiableList(new ArrayList<FindingVerdict>(perFinding));
    }

    public boolean allFalsePositive() {
        return "false_positive".equals(overallVerdict);
    }
}
