package com.example.nali.myapplication;

import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;

import javax.crypto.Cipher;



import com.example.nali.myapplication.BASE64_src.com.rt.CharacterDecoder;
import com.example.nali.myapplication.BASE64_src.com.rt.CharacterEncoder;
import com.example.nali.myapplication.BASE64_src.sun.misc.BASE64Decoder;
import com.example.nali.myapplication.BASE64_src.sun.misc.BASE64Encoder;
import com.google.common.collect.Lists;


@SuppressWarnings("restriction")
public class RSA {

    private static final String PUBLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCVhaR3Or7suUlwHUl2Ly36uVmb"
            + "oZ3+HhovogDjLgRE9CbaUokS2eqGaVFfbxAUxFThNDuXq/fBD+SdUgppmcZrIw4H"
            + "MMP4AtE2qJJQH/KxPWmbXH7Lv+9CisNtPYOlvWJ/GHRqf9x3TBKjjeJ2CjuVxlPB" + "DX63+Ecil2JR9klVawIDAQAB";

    private static final String PRIVATE_KEY = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJWFpHc6vuy5SXAd"
            + "SXYvLfq5WZuhnf4eGi+iAOMuBET0JtpSiRLZ6oZpUV9vEBTEVOE0O5er98EP5J1S"
            + "CmmZxmsjDgcww/gC0TaoklAf8rE9aZtcfsu/70KKw209g6W9Yn8YdGp/3HdMEqON"
            + "4nYKO5XGU8ENfrf4RyKXYlH2SVVrAgMBAAECgYAJ0TeGOI42nsfKm7GqF9juAGN4"
            + "y3jDKZjQjdN/FxNir6Epboffe/1hC+My3+jvZCCqlLJg+AKRY4jAJ5XVbypO3tHR"
            + "d9uLFgCjzREJ09J6SWyNj3KFKCkJ4vpaO0jbUAAtFGlLElc6ZtHNKabeJ0ECOgcI"
            + "vVsfHpP47j1GTRU8oQJBAMXsksEmrIvCJ0l5mdDX73nRJzbxDK6m7jndE4fBe0h3"
            + "Wl06iBCfuaS2x+PTjmiRWvfFu2B1/9E9Tt0jc4FQS3ECQQDBZUKZjnv6rKtwqBj1"
            + "EqjIXVF2SAsttW/6vTpg6mhHYITlrqQqrt1NJ5+6PRVQr1FLDxPArNVSdoz6MFII"
            + "AiibAkA+3K+Tt0PQM78koAGRijPePea1lYPQqOY67JN6Z6JPVtEVkTSMCx78SK1e"
            + "F+BAKAJ7dYrYzUGN5Gn65HqYFLeRAkBcBOFWjSxCjwwX03PkkBdNFtHe9NKU0iLQ"
            + "7F6tpHsvkyZI3vrv8DoOLw9aHxxYQsLscuUUJWhvD0du97TgaJ6HAkEAoRXjsQO2"
            + "UmgQcddE2e6Uxp5riOuWIEEzoW6YssCW9BznCnwXy/xamrTKhoW2cIHwn6cFx+MF" + "myaK5T0xAtF5pw==";

    private static final Charset UTF8 = Charset.forName("utf8");

    private static KeyFactory keyFactory;

    private static ThreadLocal<BASE64Decoder> base64DecoderThreadLocal = new ThreadLocal<BASE64Decoder>();

    private static ThreadLocal<BASE64Encoder> base64EncoderThreadLocal = new ThreadLocal<BASE64Encoder>();

    static {
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
        }
    }

    private RSAPublicKey publicKey;

    private ThreadLocal<Cipher> publicCipherThreadLocal = new ThreadLocal<Cipher>();

    private ThreadLocal<Cipher> publicDecryptCipherThreadLocal = new ThreadLocal<Cipher>();

    private int keyLen;

    private int keyLen2;

    private RSAPrivateKey privateKey;

    private ThreadLocal<Cipher> privateCipherThreadLocal = new ThreadLocal<Cipher>();

    private ThreadLocal<Cipher> privateEncryptCipherThreadLocal = new ThreadLocal<Cipher>();

    private int privateKeyLen;

    private int privateKeyLen2;

    public RSA() {
    }

    public RSA(RSAPublicKey publicKey) {
        setPublicKey(publicKey);
    }

    public RSA(RSAPrivateKey privateKey) {
        setPrivateKey(privateKey);
    }

    public RSA(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
        if (publicKey != null)
            setPublicKey(publicKey);
        if (privateKey != null)
            setPrivateKey(privateKey);
    }

    public void setPublicKey(RSAPublicKey publicKey) {
        this.publicKey = publicKey;
        keyLen2 = publicKey.getModulus().bitLength() / 8;
        keyLen = keyLen2 - 11;
    }

    public void setPrivateKey(RSAPrivateKey privateKey) {
        this.privateKey = privateKey;
        privateKeyLen2 = privateKey.getModulus().bitLength() / 8;
        privateKeyLen = privateKeyLen2 - 11;
    }

    /**
      * 实例化公钥
      */
    public static RSAPublicKey getPublicKey(String pubKey) {
        try {


            byte[] encodedKey = Base64.decode(pubKey, Base64.DEFAULT);
           // byte[] encodedKey = getBASE64Decoder().decodeBuffer(pubKey);
            KeySpec keySpec = new X509EncodedKeySpec(encodedKey);
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static CharacterDecoder getBASE64Decoder() {
        BASE64Decoder base64Decoder = base64DecoderThreadLocal.get();
        if (base64Decoder == null) {
            base64Decoder = new BASE64Decoder();
            base64DecoderThreadLocal.set(base64Decoder);
        }

        return base64Decoder;
    }

    public static RSAPublicKey getPublicKey() {
        return getPublicKey(PUBLIC_KEY);
    }

    /**
     * 实例化私钥
     */
    public static RSAPrivateKey getPrivateKey(String priKey) {
        try {
            byte[] encodedKey = Base64.decode(priKey, Base64.DEFAULT);
           // byte[] encodedKey = getBASE64Decoder().decodeBuffer(priKey);
            KeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
            KeySpec keySpecD = new X509EncodedKeySpec(encodedKey);
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static RSAPrivateKey getPrivateKey() {
        return getPrivateKey(PRIVATE_KEY);
    }

    /** 
     * 生成公钥和私钥 
     */
    public static RSAStringKeyPair generateKeys() {
        RSAStringKeyPair stringKeyPair = new RSAStringKeyPair();
        try {
            KeyPairGenerator keyPairGen;
            keyPairGen = KeyPairGenerator.getInstance("RSA");
            keyPairGen.initialize(1024);
            KeyPair keyPair = keyPairGen.generateKeyPair();
            String publicKey = getBASE64Encoder().encodeBuffer(keyPair.getPublic().getEncoded());
            String privateKey = getBASE64Encoder().encodeBuffer(keyPair.getPrivate().getEncoded());
            stringKeyPair.setPrivateKey(privateKey);
            stringKeyPair.setPublicKey(publicKey);
        } catch (NoSuchAlgorithmException e) {
        }
        return stringKeyPair;
    }

    private static CharacterEncoder getBASE64Encoder() {
        BASE64Encoder base64Encoder = base64EncoderThreadLocal.get();
        if (base64Encoder == null) {
            base64Encoder = new BASE64Encoder();
            base64EncoderThreadLocal.set(base64Encoder);
        }
        return base64Encoder;
    }

    /** 
     * 公钥加密 
     */
    public static String encryptByPublicKey(String data, RSAPublicKey publicKey) {
        return new RSA(publicKey, null).encryptByPublicKey(data);
    }

    /** 
     * 私钥解密 
     */
    public static String decryptByPrivateKey(String data, RSAPrivateKey privateKey) {
        return new RSA(privateKey).decryptByPrivateKey(data);
    }

    /** 
     * 公钥加密 
     */
    public String encryptByPublicKey(String data) {
        Cipher cipher = getPublicEncryptCipher();
//        StringBuilder sb = new StringBuilder();
//        byte[] bytes = data.getBytes(UTF8);
//        ByteArrayOutputStream osa = new ByteArrayOutputStream();
//        int len = bytes.length > keyLen ? keyLen : bytes.length;
//        for (int i = 0; i < bytes.length; i += keyLen) {
//            len = len > bytes.length - i ? bytes.length - i : len;
//            byte[] output = doFinal(bytes, i, len, cipher);
//            try {
//                osa.write(output);
//            } catch (IOException e) {
//                // ignore
//                throw new RuntimeException(e.getMessage(), e.getCause());
//            }
//        }


        // modify by rick at 2016-09-21
        // 直接base64，分段base64中间不满3字节产生的补全字符，在其他语言中无法验证通过，改成直接加密并base64。
       // return getBASE64Encoder().encodeBuffer(osa.toByteArray());

        StringBuilder sb = new StringBuilder();
        byte[] bytes;
        bytes = data.getBytes(Charset.forName("UTF-8"));
        int len = bytes.length > keyLen ? keyLen : bytes.length;
        try {
            for (int i = 0; i < bytes.length; i += keyLen) {
                len = len > bytes.length - i ? bytes.length - i : len;
                byte[] output = cipher.doFinal(bytes, i, len);
                sb.append(new String(Base64.encode(output, Base64.DEFAULT)));
            }
        }catch (Exception e){
            e.printStackTrace();
        }

        String result = sb.toString();
        Log.i("XMLYPLAY","result:"+result);

        return result;
    }

    private Cipher getPublicEncryptCipher() {
        Cipher cipher = publicCipherThreadLocal.get();
        if (cipher == null) {
            try {
               // cipher = Cipher.getInstance("RSA");
                cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                publicCipherThreadLocal.set(cipher);
                cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        return cipher;
    }

    /** 
     * 私钥加密 
     */
    public String encryptByPrivateKey(String data) {
        Cipher cipher = getPrivateEncryptCipher();
        byte[] bytes = data.getBytes(UTF8);
        ByteArrayOutputStream osa = new ByteArrayOutputStream();
        int len = bytes.length > privateKeyLen ? privateKeyLen : bytes.length;
        for (int i = 0; i < bytes.length; i += privateKeyLen) {
            len = len > bytes.length - i ? bytes.length - i : len;
            byte[] output = doFinal(bytes, i, len, cipher);
            try {
                osa.write(output);
            } catch (IOException e) {
                // ignore
                throw new RuntimeException(e.getMessage(), e.getCause());
            }
        }
        // modify by rick at 2016-09-21
        // 直接base64，分段base64中间不满3字节产生的补全字符，在其他语言中无法验证通过，改成直接加密并base64。
        return getBASE64Encoder().encodeBuffer(osa.toByteArray());
    }

    private Cipher getPrivateEncryptCipher() {
        Cipher cipher = privateEncryptCipherThreadLocal.get();
        if (cipher == null) {
            try {
                cipher = Cipher.getInstance("RSA");
                cipher.init(Cipher.ENCRYPT_MODE, privateKey);
                privateEncryptCipherThreadLocal.set(cipher);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        return cipher;
    }

    /** 
     * 公钥解密 
     */
    public String decryptByPublicKey(String data) {
        Cipher cipher = getPublicDecryptCipher();
        byte[] bytes = decodeBuffer(data);
        List<byte[]> out = Lists.newLinkedList();
        int len = 0;
        for (int i = 0; i < bytes.length; i += keyLen2) {
            int length = keyLen2 > bytes.length - i ? bytes.length - i : keyLen2;
            byte[] src = doFinal(bytes, i, length, cipher);
            out.add(src);
            len += src.length;
        }
        byte[] bs = new byte[len];
        int destPos = 0;
        for (byte[] e : out) {
            System.arraycopy(e, 0, bs, destPos, e.length);
            destPos += e.length;
        }
        return new String(bs, UTF8);
    }

    private byte[] doFinal(byte[] input, int inputOffset, int inputLen, Cipher cipher) {
        try {
            return cipher.doFinal(input, inputOffset, inputLen);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private Cipher getPublicDecryptCipher() {
        Cipher cipher = publicDecryptCipherThreadLocal.get();
        if (cipher == null) {
            try {
                cipher = Cipher.getInstance("RSA");
                cipher.init(Cipher.DECRYPT_MODE, publicKey);
                publicDecryptCipherThreadLocal.set(cipher);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        return cipher;
    }

    /** 
     * 私钥解密 
     */
    public String decryptByPrivateKey(String data) {
        Cipher cipher = getPrivateDecryptCipher();
       // byte[] bytes = decodeBuffer(data);
        byte[] bytes = Base64.decode(data, Base64.DEFAULT);
        List<byte[]> out = Lists.newLinkedList();
        int len = 0;
        for (int i = 0; i < bytes.length; i += privateKeyLen2) {
            int length = privateKeyLen2 > bytes.length - i ? bytes.length - i : privateKeyLen2;
            byte[] src = doFinal(bytes, i, length, cipher);
            out.add(src);
            len += src.length;
        }
        byte[] bs = new byte[len];
        int destPos = 0;
        for (byte[] e : out) {
            System.arraycopy(e, 0, bs, destPos, e.length);
            destPos += e.length;
        }
        return new String(bs, UTF8);
    }

    private byte[] decodeBuffer(String data) {
        try {
            return getBASE64Decoder().decodeBuffer(data);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private Cipher getPrivateDecryptCipher() {
        Cipher cipher = privateCipherThreadLocal.get();
        if (cipher == null) {
            try {
               // cipher = Cipher.getInstance("RSA");
                cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.DECRYPT_MODE, privateKey);
                privateCipherThreadLocal.set(cipher);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        return cipher;
    }

    public static class RSAStringKeyPair {

        private String publicKey;

        private String privateKey;

        public String getPublicKey() {
            return publicKey;
        }

        public void setPublicKey(String publicKey) {
            this.publicKey = publicKey;
        }

        public String getPrivateKey() {
            return privateKey;
        }

        public void setPrivateKey(String privateKey) {
            this.privateKey = privateKey;
        }

    }


    public static void main(String[] args) {
        RSAPublicKey publicKey = getPublicKey();
        System.out.println(PUBLIC_KEY);
        RSA rsaPk=new RSA(RSA.getPublicKey());
        String encryptByPublicKey = rsaPk.encryptByPublicKey("123456");
        System.out.println(encryptByPublicKey);
//        System.out.println();
//        System.out.println("================");
//        RSAPrivateKey privateKey = getPrivateKey();
//        RSA rsa = new RSA(publicKey, privateKey);
//        String s="feGHbdtSO0kFZHJzQxm9/hy6U3ugt0uRxavz00CWc60bGotl15LR6qIOj1faInB7E2cGPQUokhWQyiV7h3t0l08xacn5Y1F7rJNRYqWVw0inqJ7b7LWRKlm6D1Y+hi+XA9r6sXpSz4bhoIWpcudXH4ShRp7A9W7Zm0DHngO26vM=";
//        String decryptByPrivateKey = rsa.decryptByPrivateKey(s);
//        System.out.println(decryptByPrivateKey);
//        String data = "123123123123";
//        String ciphertext = rsa.encryptByPublicKey(data);
//        System.out.println(ciphertext);
//        String plaintext = rsa.decryptByPrivateKey(ciphertext);
//        System.out.println(plaintext);
        
//        plaintext = rsa.decryptByPublicKey(ciphertext);
//        System.out.println(plaintext);
    }


}
