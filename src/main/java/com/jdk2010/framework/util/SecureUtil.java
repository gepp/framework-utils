package com.jdk2010.framework.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;
import java.util.zip.CRC32;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import com.sun.xml.internal.messaging.saaj.packaging.mime.util.BASE64EncoderStream;

/**
 * 安全相关的工具类，包括各种加密算法
 * 
 *
 */
public class SecureUtil {

    private static String strkey = "4C324F5A4F454242";

    /**
     * 获得指定字符串的MD5码
     * 
     * @param key 字符串
     * @return MD5
     */
    public static String md5(String key) {
        return digest(ALGORITHM.MD5, key);
    }

    public static String tomd5(String plainText) {
        String str = "";
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(plainText.getBytes());
            byte b[] = md.digest();

            int i;

            StringBuffer buf = new StringBuffer("");
            for (int offset = 0; offset < b.length; offset++) {
                i = b[offset];
                if (i < 0)
                    i += 256;
                if (i < 16)
                    buf.append("0");
                buf.append(Integer.toHexString(i));
            }
            str = buf.toString();
            // System.out.println("result: " + buf.toString());// 32位的加密
            // System.out.println("result: " + buf.toString().substring(8,
            // 24));// 16位的加密
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();

        }
        return str;
    }

    public static String sha1(String key) {
        return digest(ALGORITHM.SHA1, key);
    }

    /**
     * 对给定的byte数组做base64编码
     * 
     * @param bytes byte数组
     * @return base64编码
     */
    public static String base64Encode(byte[] bytes) {
        return new String(BASE64EncoderStream.encode(bytes));
    }

    public static long crc32(String key) {
        CRC32 crc32 = new CRC32();
        crc32.update(key.getBytes());
        return crc32.getValue();
    }

    /**
     * 计算指定加密算法后生成的结果
     * 
     * @param algorithm 加密算法枚举
     * @param key 字符串
     * @return 加密后的结果
     */
    private static String digest(ALGORITHM algorithm, String key) {
        MessageDigest instance = null;
        try {
            instance = MessageDigest.getInstance(algorithm.toString());
        } catch (NoSuchAlgorithmException e) {
            System.out.println("No such Algorit!");
            return null;
        }
        if (instance != null) {
            instance.update(key.getBytes());
            return new String(BASE64EncoderStream.encode(instance.digest()));
        }
        return null;
    }

    private static BASE64Encoder base64 = new BASE64Encoder();
    private static byte[] myIV = { 50, 51, 52, 53, 54, 55, 56, 57 };

    protected static MessageDigest messagedigest = null;
    protected static char[] hexDigits = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e',
            'f' };
    static {
        try {
            messagedigest = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("MD5FileUtil messagedigest初始化失败");
        }
    }

    /**
     * 3des加密
     * 
     * @param input
     * @return
     * @throws Exception
     */
    public static String desEncrypt(String input) throws Exception {
        BASE64Decoder base64d = new BASE64Decoder();
        DESedeKeySpec p8ksp = null;
        p8ksp = new DESedeKeySpec(base64d.decodeBuffer(strkey));
        Key key = null;
        key = SecretKeyFactory.getInstance("DESede").generateSecret(p8ksp);
        byte[] plainBytes = (byte[]) null;
        Cipher cipher = null;
        byte[] cipherText = (byte[]) null;
        plainBytes = input.getBytes("UTF8");
        cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        SecretKeySpec myKey = new SecretKeySpec(key.getEncoded(), "DESede");
        IvParameterSpec ivspec = new IvParameterSpec(myIV);
        cipher.init(1, myKey, ivspec);
        cipherText = cipher.doFinal(plainBytes);
        return removeBR(base64.encode(cipherText));
    }

    /**
     * 3des解密
     * 
     * @param input
     * @return
     * @throws Exception
     */
    public static String desDecrypt(String cipherText) throws Exception {
        BASE64Decoder base64d = new BASE64Decoder();
        DESedeKeySpec p8ksp = null;
        p8ksp = new DESedeKeySpec(base64d.decodeBuffer(strkey));
        Key key = null;
        key = SecretKeyFactory.getInstance("DESede").generateSecret(p8ksp);
        Cipher cipher = null;
        byte[] inPut = base64d.decodeBuffer(cipherText);
        cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        SecretKeySpec myKey = new SecretKeySpec(key.getEncoded(), "DESede");
        IvParameterSpec ivspec = new IvParameterSpec(myIV);
        cipher.init(2, myKey, ivspec);
        byte[] output = cipher.doFinal(inPut);
        return new String(output, "UTF8");
    }

    private static String removeBR(String str) {
        StringBuffer sf = new StringBuffer(str);
        for (int i = 0; i < sf.length(); i++) {
            if (sf.charAt(i) == '\n') {
                sf = sf.deleteCharAt(i);
            }
        }
        for (int i = 0; i < sf.length(); i++) {
            if (sf.charAt(i) == '\r')
                sf = sf.deleteCharAt(i);
        }
        return sf.toString();
    }

    /**
     * 文件MD5加密
     * 
     * @param file
     * @return
     * @throws IOException
     */
    public static String getFileMD5String(File file) throws IOException {
        FileInputStream in = new FileInputStream(file);
        FileChannel ch = in.getChannel();
        MappedByteBuffer byteBuffer = ch.map(FileChannel.MapMode.READ_ONLY, 0L, file.length());
        messagedigest.update(byteBuffer);
        return bufferToHex(messagedigest.digest());
    }

    private static String bufferToHex(byte[] bytes) {
        return bufferToHex(bytes, 0, bytes.length);
    }

    private static String bufferToHex(byte[] bytes, int m, int n) {
        StringBuffer stringbuffer = new StringBuffer(2 * n);
        int k = m + n;
        for (int l = m; l < k; l++) {
            appendHexPair(bytes[l], stringbuffer);
        }
        return stringbuffer.toString();
    }

    private static void appendHexPair(byte bt, StringBuffer stringbuffer) {
        char c0 = hexDigits[((bt & 0xF0) >> 4)];
        char c1 = hexDigits[(bt & 0xF)];
        stringbuffer.append(c0);
        stringbuffer.append(c1);
    }

    public static String getUUID() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    /**
     * 加密算法枚举
     * 
     * @author
     *
     */
    enum ALGORITHM {
        MD5, SHA1;
    }

    public static void main(String[] args) throws Exception {
        String xml = "<?xml version=\"1.0\" encoding=\"utf-8\"?><BUSINESS ID=\"INIT\"><NSRXX><SFZH/><DLMM/><JQBH>016000000031</JQBH><YWSQM>L2OZOEBB</YWSQM></NSRXX></BUSINESS>";
        String returnXML = "7AiBjTKqqzX6mAd3aav6/LwEnA+3Zzeis2+rNbGt0vuxAjUvoUSBtvx6htGrNfXUNCxA2oOV2k2DY231F2AOVT6P3lLoO3CMQhVtaYFOS5YGT3dlyyy4Lm250L/Lapu39nOkC46kwPFW4uFlORehI10fNj0fss1w9qkb7XjHr1QhIO2r/LeCsi3nQlXJCMm2aMe9BENm7diGypph/90Q+lrjGMtRc4G4kBuaNnW/LYmsr8sumQPD6w/wB4q0v34Shv6GvfGsaz9fTm+zdJlSL4S/C9cb3VRjqfyoyL2Ot+YvANNpP7S7Cm2+FD0TMkOc1841san83Gv0b29eepeXgrCyrkW0gHTSiy5BHp6Gjcl4N5oBanSMI6q52/k/g2jvvhQ+jCcd/NjfGOo8OjQ+UJxI/G0Sf6NiZV4sK9JWGDKnSy7ZPgxQhutbbgl5anGsEBe3VUioz4PGumknNXAF1CZM9rhhm099ABpANm5ltnL8eobRqzX11JsyOYKNSS/C";
        // desDecrypt(xml);
        desEncrypt(xml);

    }
}
