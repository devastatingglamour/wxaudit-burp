package wxaudit;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** In-memory wxapkg parser. No files are written to disk. */
public final class Wxapkg {

    public static final class VirtualFile {
        public final String name;
        public final byte[] data;
        public VirtualFile(String name, byte[] data) { this.name = name; this.data = data; }
    }

    public static final class UnpackResult {
        public boolean encrypted;
        public int fileCount;
        public List<VirtualFile> files = new ArrayList<VirtualFile>();
        public String detectedAppId;
    }

    private static final Pattern APPID_RE = Pattern.compile("wx[0-9a-fA-F]{16}");

    private Wxapkg() { }

    public static UnpackResult unpack(byte[] raw, String wxidHint) throws Exception {
        UnpackResult result = new UnpackResult();
        byte[] data = raw;
        if (!Crypto.isPlainWxapkg(data)) {
            result.encrypted = true;
            data = Crypto.decryptWxapkg(raw, wxidHint);
            if (!Crypto.isPlainWxapkg(data)) {
                throw new Exception("解密后魔数仍不匹配，未得到合法 wxapkg（AppID 可能不对）");
            }
        }
        if (data.length < 18) throw new Exception("wxapkg 头部被截断");

        ByteBuffer bb = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN);
        int indexLength = bb.getInt(5);
        int dataLength = bb.getInt(9);
        int count = bb.getInt(14);
        result.fileCount = count;
        if (count < 0 || count > 200000) throw new Exception("文件数异常: " + count);
        int pos = 18;
        for (int i = 0; i < count; i++) {
            if (pos + 4 > data.length) throw new Exception("索引表被截断");
            int nameLen = bb.getInt(pos);
            pos += 4;
            if (nameLen < 0 || nameLen > 4096 || pos + nameLen + 8 > data.length) throw new Exception("文件名长度异常");
            String name = new String(data, pos, nameLen, StandardCharsets.UTF_8).replace('\\', '/');
            pos += nameLen;
            int off = bb.getInt(pos);
            int size = bb.getInt(pos + 4);
            pos += 8;
            if (off < 0 || size < 0 || off + size > data.length) continue;
            while (name.startsWith("/")) name = name.substring(1);
            if (name.isEmpty()) name = "unnamed-" + i;
            byte[] body = new byte[size];
            System.arraycopy(data, off, body, 0, size);
            result.files.add(new VirtualFile(name, body));
            if (result.detectedAppId == null) {
                Matcher m = APPID_RE.matcher(new String(body, 0, body.length, StandardCharsets.ISO_8859_1));
                if (m.find()) result.detectedAppId = m.group();
            }
        }
        // Prefer an explicit "appid" field from app-config.json
        for (VirtualFile vf : result.files) {
            if (vf.name.endsWith("app-config.json")) {
                Matcher m = APPID_RE.matcher(new String(vf.data, StandardCharsets.ISO_8859_1));
                if (m.find()) { result.detectedAppId = m.group(); break; }
            }
        }
        return result;
    }

    /** Build a synthetic plaintext wxapkg from in-memory files (for self-test). */
    public static byte[] buildPlainPackage(List<VirtualFile> files) {
        int indexEntries = 0;
        for (VirtualFile f : files) indexEntries += 4 + f.name.getBytes(StandardCharsets.UTF_8).length + 8;
        int dataStart = 18 + indexEntries;
        byte[] index = new byte[indexEntries];
        byte[] body = new byte[files.size() == 0 ? 0 : totalSize(files)];
        ByteBuffer ib = ByteBuffer.wrap(index).order(ByteOrder.BIG_ENDIAN);
        int cur = dataStart;
        int bodyPos = 0;
        for (VirtualFile f : files) {
            byte[] nb = f.name.getBytes(StandardCharsets.UTF_8);
            ib.putInt(nb.length); ib.put(nb); ib.putInt(cur); ib.putInt(f.data.length);
            System.arraycopy(f.data, 0, body, bodyPos, f.data.length);
            bodyPos += f.data.length;
            cur += f.data.length;
        }
        ByteBuffer out = ByteBuffer.allocate(18 + index.length + body.length).order(ByteOrder.BIG_ENDIAN);
        out.put((byte) 0xBE); out.putInt(0); out.putInt(index.length); out.putInt(body.length); out.put((byte) 0xED);
        out.putInt(files.size()); out.put(index); out.put(body);
        return out.array();
    }

    private static int totalSize(List<VirtualFile> files) {
        int n = 0;
        for (VirtualFile f : files) n += f.data.length;
        return n;
    }
}
