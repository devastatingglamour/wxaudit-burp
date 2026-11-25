package wxaudit;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 内存态 AI 结果仓库 / In-memory AI result store.
 *
 * <p>以 packetId 为键，线程安全，不落盘。/ Keyed by packetId, thread-safe, never persisted.
 */
public final class AiResultStore {
    private final ConcurrentHashMap<String, AiResult> map = new ConcurrentHashMap<String, AiResult>();

    public void put(AiResult r) {
        if (r == null || r.packetId.isEmpty()) return;
        map.put(r.packetId, r);
    }

    public AiResult get(String packetId) {
        return packetId == null ? null : map.get(packetId);
    }

    public boolean has(String packetId) {
        return packetId != null && map.containsKey(packetId);
    }

    public int size() {
        return map.size();
    }

    public void clear() {
        map.clear();
    }

    /** 返回所有结果的快照（顺序不保证）。 */
    public List<AiResult> all() {
        return Collections.unmodifiableList(new ArrayList<AiResult>(map.values()));
    }

    /** 统计误报数（overallVerdict == false_positive）。 */
    public int falsePositiveCount() {
        int n = 0;
        for (AiResult r : map.values()) {
            if (r.triage != null && r.triage.allFalsePositive()) n++;
        }
        return n;
    }
}
