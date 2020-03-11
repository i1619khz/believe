package org.believe.security;

/**
 * @author WangYi
 * @version 1.0
 * @since 2019/2/14
 */
public interface AuthorizationConstants {
  String ROLE_USER = "ROLE_USER";
  String ROLE_ADMIN = "ROLE_ADMIN";
  String ROLE_SUPER_ADMIN = "ROLE_SUPER_ADMIN";

  String TOKEN_HEADER = "Authorization";
  String TOKEN_NAME = "AuthToken";

  String PUBLIC_KEY = "publicKey";
  String PRIVATE_KEY = "privateKey";

  String KEY_ALGORITHM = "RSA";
  String CIPHER_ALGORITHM = "RSA/ECB/PKCS1Padding";

  String PUBLIC_KEY_RESOURCE_PATH = "/pubKey.txt";
  String PRIVATE_KEY_RESOURCE_PATH = "/priKey.txt";

  String JWT_SECRET = "fleece@auth";
  String API_SECURITY_CONTEXT_PREFIX = "api@";

  /**
   * RSA密钥长度必须是64的倍数，在512~65536之间。默认是1024
   */
  int KEY_SIZE = 2048;
}
