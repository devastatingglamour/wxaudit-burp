package wxaudit;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Standalone verification of the core modules. No Burp API required. */
public class SelfTest {

    static int failed = 0;

    static void check(boolean ok, String label) {
        System.out.println((ok ? "  OK   " : "  FAIL ") + label);
        if (!ok) failed++;
    }

    public static void main(String[] args) throws Exception {
        System.out.println("1) ScopeFilter target matching");
        ScopeFilter sf = new ScopeFilter();
        check(!sf.isConfigured(), "no target configured => match nothing");
        sf.configure("# engagement A\ntarget-corp.cn, *.other.com\nhttps://strict-only.com/app/v1\n");
        check(sf.matches("https://api.target-corp.cn/v1/user"), "subdomain of target-corp.cn matched");
        check(sf.matches("http://target-corp.cn"), "apex domain matched");
        check(!sf.matches("https://evil.com/"), "unrelated host rejected");
        check(sf.matches("https://x.other.com/a"), "*.other.com matched");
        check(!sf.matches("https://other.com/a"), "*.other.com excludes apex unless listed");
        check(sf.matches("https://strict-only.com/app/v1/page"), "path prefix matched");
        check(!sf.matches("https://strict-only.com/elsewhere"), "path prefix enforced");
        check(!sf.matches("not-a-url"), "malformed URL rejected");

        System.out.println("2) Plain wxapkg unpack");
        String appId = "wx1234567890abcdef";
        String config = "{\"appid\":\"" + appId + "\",\"page\":{\"pages/index/index\":{},\"pages/admin/panel\":{}}}";
        String js = "var API_BASE='https://api.target-corp.cn/v2';var ak='LTAI5tABCDEFGHIJKLMNOP';"
                + "wx.request({url:API_BASE+'/user/info',method:'POST'});var phone='13812345678';"
                + "var SECRET='abc123secretkey987654';axios('/api/v1/orders');"
                + "wx.uploadFile({url:'https://upload.target-corp.cn/up',filePath:'/tmp/a'});";
        StringBuilder padding = new StringBuilder();
        for (int i = 0; i < 100; i++) padding.append("// filler line for package size\n");
        String bigJs = js + padding;
        List<Wxapkg.VirtualFile> src = new ArrayList<Wxapkg.VirtualFile>();
        src.add(new Wxapkg.VirtualFile("app-config.json", config.getBytes(StandardCharsets.UTF_8)));
        src.add(new Wxapkg.VirtualFile("app-service.js", bigJs.getBytes(StandardCharsets.UTF_8)));
        byte[] pkg = Wxapkg.buildPlainPackage(src);
        check(Crypto.isPlainWxapkg(pkg), "plaintext header magic 0xBE/0xED");
        Wxapkg.UnpackResult plain = Wxapkg.unpack(pkg, null);
        check(plain.fileCount == 2 && plain.files.size() == 2, "2 files unpacked");
        check(appId.equals(plain.detectedAppId), "appid auto-extracted from app-config.json");

        System.out.println("3) Secret / endpoint scanning");
        List<Scanner.Finding> findings = Scanner.scanPackageFiles(plain.files, "https://api.target-corp.cn/pkg");
        List<String> rules = new ArrayList<String>();
        for (Scanner.Finding f : findings) if (!rules.contains(f.rule)) rules.add(f.rule);
        check(rules.contains("cloud_ak"), "cloud AccessKey detected");
        check(rules.contains("secret_assign"), "hardcoded secret detected");
        check(rules.contains("phone"), "phone number detected");
        check(rules.contains("abs_url"), "absolute URL detected");
        check(rules.contains("wx_request"), "wx.request target detected");
        check(findings.get(0).severity.equals("high"), "high severity sorted first");
        check(Scanner.extractRoutes(plain.files).contains("pages/admin/panel"), "hidden admin route detected");

        System.out.println("4) Encrypted wxapkg roundtrip");
        byte[] encrypted = encryptForTest(pkg, appId);
        check(!Crypto.isPlainWxapkg(encrypted), "encrypted package has no plaintext magic");
        byte[] roundtrip = Crypto.decryptWxapkg(encrypted, appId);
        check(Arrays.equals(pkg, roundtrip), "raw byte roundtrip identical");
        Wxapkg.UnpackResult decrypted = Wxapkg.unpack(encrypted, appId);
        check(decrypted.encrypted && decrypted.files.size() == 2, "encrypted package decrypted and unpacked");
        check(decrypted.files.size() > 1 && new String(decrypted.files.get(1).data, StandardCharsets.UTF_8).contains("LTAI5t"),
                "decrypted JS content identical");
        boolean wrongIdRejected = false;
        try { Wxapkg.unpack(encrypted, "wx0000000000000000"); }
        catch (Exception ex) { wrongIdRejected = true; }
        check(wrongIdRejected, "wrong AppID rejected with clear error");
        boolean missingIdRejected = false;
        try { Wxapkg.unpack(encrypted, null); }
        catch (Exception ex) { missingIdRejected = true; }
        check(missingIdRejected, "missing AppID rejected with clear error");

        System.out.println();
        if (failed == 0) System.out.println("ALL CORE SELF-TESTS PASSED");
        else { System.out.println(failed + " TEST(S) FAILED"); System.exit(1); }
    }

    /** Build a PC-WeChat style encrypted package from a plaintext package. */
    private static byte[] encryptForTest(byte[] plain, String wxid) throws Exception {
        KeySpec spec = new PBEKeySpec(wxid.toCharArray(), Crypto.SALT.getBytes(StandardCharsets.UTF_8), 1000, 256);
        byte[] key = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1").generateSecret(spec).getEncoded();
        Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                new IvParameterSpec(Crypto.IV.getBytes(StandardCharsets.UTF_8)));
        byte[] aesPart = c.doFinal(plain, 0, 1024);
        int xor = wxid.charAt(wxid.length() - 2) & 0xFF;
        // Encrypted layout: 6-byte prefix + AES(plain[0:1024]) + XOR(plain[1024:])
        byte[] tail = Arrays.copyOfRange(plain, 1024, plain.length);
        for (int i = 0; i < tail.length; i++) tail[i] = (byte) (tail[i] ^ xor);
        byte[] out = new byte[6 + aesPart.length + tail.length];
        out[0] = 0x42; out[1] = 0x4d; out[2] = 0x56; // arbitrary prefix, ignored by decryptor
        System.arraycopy(aesPart, 0, out, 6, aesPart.length);
        System.arraycopy(tail, 0, out, 6 + aesPart.length, tail.length);
        return out;
    }
}
