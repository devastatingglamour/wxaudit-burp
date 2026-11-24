package wxaudit;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import java.util.Arrays;

/** WeChat PC wxapkg decryption using only the JDK crypto providers. */
public final class Crypto {

    public static final String SALT = "saltiest";
    public static final String IV = "the iv: 16 bytes";
    private static final int AES_BLOCK = 16;
    private static final int HEADER_LEN = 1030; // 6-byte prefix + 1024-byte AES block

    private Crypto() { }

    /**
     * Decrypt a PC-WeChat cached wxapkg.
     * key  = PBKDF2-HMAC-SHA1(wxid, "saltiest", 1000, 32)
     * body = AES-256/CBC/NoPadding(data[6:1030], IV="the iv: 16 bytes") + XOR(data[1030:], wxid[-2])
     */
    public static byte[] decryptWxapkg(byte[] data, String wxid) throws CryptoException {
        if (data == null || data.length < HEADER_LEN) {
            throw new CryptoException("包太小，无法解密（长度 " + (data == null ? 0 : data.length) + " < " + HEADER_LEN + "）");
        }
        if (wxid == null || wxid.length() < 3) {
            throw new CryptoException("该包疑似加密包，未获取到有效 AppID（wxid）；请在面板手动填入后重试");
        }
        try {
            KeySpec spec = new PBEKeySpec(wxid.toCharArray(), SALT.getBytes(StandardCharsets.UTF_8), 1000, 256);
            byte[] keyBytes = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1").generateSecret(spec).getEncoded();
            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV.getBytes(StandardCharsets.UTF_8)));
            byte[] aesPart = cipher.doFinal(data, 6, 1024);
            int xorKey = wxid.charAt(wxid.length() - 2) & 0xFF;
            byte[] tail = Arrays.copyOfRange(data, HEADER_LEN, data.length);
            for (int i = 0; i < tail.length; i++) tail[i] = (byte) (tail[i] ^ xorKey);
            byte[] out = new byte[aesPart.length + tail.length];
            System.arraycopy(aesPart, 0, out, 0, aesPart.length);
            System.arraycopy(tail, 0, out, aesPart.length, tail.length);
            return out;
        } catch (Exception ex) {
            throw new CryptoException("解密失败（AppID 可能不正确或包格式不匹配）: " + ex.getMessage(), ex);
        }
    }

    /** True when the bytes look like a plaintext wxapkg (0xBE ... 0xED @13). */
    public static boolean isPlainWxapkg(byte[] data) {
        return data != null && data.length >= 18 && (data[0] & 0xFF) == 0xBE && (data[13] & 0xFF) == 0xED;
    }

    /** Gzip magic bytes (Burp sometimes hands back raw compressed bodies). */
    public static boolean isGzip(byte[] data) {
        return data != null && data.length >= 2 && (data[0] & 0xFF) == 0x1f && (data[1] & 0xFF) == 0x8b;
    }

    public static class CryptoException extends Exception {
        public CryptoException(String message) { super(message); }
        public CryptoException(String message, Throwable cause) { super(message, cause); }
    }
}
