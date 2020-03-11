package org.believe.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import static org.believe.security.AuthorizationConstants.CIPHER_ALGORITHM;
import static org.believe.security.AuthorizationConstants.KEY_ALGORITHM;

/**
 * @author WangYi
 * @version 1.0
 * @since 2019/2/19
 */
@Component
public class SecurityRsaAlgorithm {

  private static final Logger log = LoggerFactory.getLogger(SecurityRsaAlgorithm.class);

  /**
   * 生成密钥对。注意这里是生成密钥对KeyPair，再由密钥对获取公私钥
   *
   * @return
   */
  public Map<String, byte[]> generateKeyBytes() {
    try {
      final KeyPairGenerator keyPairGenerator = KeyPairGenerator
              .getInstance(KEY_ALGORITHM);
      keyPairGenerator.initialize(AuthorizationConstants.KEY_SIZE);
      final KeyPair keyPair = keyPairGenerator.generateKeyPair();
      final RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
      final RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

      final Map<String, byte[]> keyMap = new HashMap<>();
      keyMap.put(AuthorizationConstants.PUBLIC_KEY, publicKey.getEncoded());
      keyMap.put(AuthorizationConstants.PRIVATE_KEY, privateKey.getEncoded());
      return keyMap;
    } catch (NoSuchAlgorithmException e) {
      log.error("No such algorithm exception", e);
    }
    return null;
  }

  /**
   * 还原公钥，X509EncodedKeySpec 用于构建公钥的规范
   *
   * @param keyBytes
   * @return
   */
  public PublicKey restorePublicKey(final byte[] keyBytes) {
    final X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyBytes);
    try {
      final KeyFactory factory = KeyFactory.getInstance(KEY_ALGORITHM);
      return factory.generatePublic(x509EncodedKeySpec);
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      log.error("Restore public key An exception occurs", e);
    }
    return null;
  }

  /**
   * 还原私钥，PKCS8EncodedKeySpec 用于构建私钥的规范
   *
   * @param keyBytes
   * @return
   */
  public PrivateKey restorePrivateKey(final byte[] keyBytes) {
    final PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
            keyBytes);
    try {
      final KeyFactory factory = KeyFactory.getInstance(KEY_ALGORITHM);
      return factory.generatePrivate(pkcs8EncodedKeySpec);
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      log.error("Restore private key an exception occurs", e);
    }
    return null;
  }

  /**
   * 加密，三步走。
   *
   * @param key
   * @param plainText
   * @return
   */
  public byte[] rsaEncode(final PublicKey key, final byte[] plainText) {
    try {
      Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
      cipher.init(Cipher.ENCRYPT_MODE, key);
      return cipher.doFinal(plainText);
    } catch (NoSuchAlgorithmException | NoSuchPaddingException
            | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
      log.error("Rsa encode an exception occurs", e);
    }
    return null;
  }

  /**
   * 解密，三步走。
   *
   * @param key
   * @param encodedText
   * @return
   */
  public String rsaDecode(final PrivateKey key, final byte[] encodedText) {
    try {
      final Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
      cipher.init(Cipher.DECRYPT_MODE, key);
      return new String(cipher.doFinal(encodedText));
    } catch (NoSuchAlgorithmException | NoSuchPaddingException
            | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
      log.error("Rsa decode an exception occurs", e);
    }
    return null;
  }
}
