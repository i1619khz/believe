package org.believe.security.auth;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import lombok.extern.slf4j.Slf4j;
import org.believe.security.AuthorizationConstants;
import org.believe.security.SecurityRsaAlgorithm;
import org.believe.toolkit.JwtTokenDetector;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;
import org.springframework.util.Base64Utils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.time.LocalDate;
import java.util.Date;
import java.util.HashMap;

@Slf4j
@Component
public class AuthService {

  @Autowired
  private JwtTokenDetector jwtTokenUtils;

  @Autowired
  private AuthRepository authRepository;

  @Autowired
  private AuthenticationManager authenticationManager;

  @Autowired
  private SecurityRsaAlgorithm securityRsaAlgorithm;

  /**
   * 效验凭证
   *
   * @param userName
   * @param password
   */
  public String loginAndGenerateToken(String userName, String password) {
    Assert.notNull(userName, "userName can not be null");
    Assert.notNull(password, "password can not be null");
    final String decodePassword = decodeRasPwdToPlainText(password);
    final String token = generationJwtStr(userName);
    UsernamePasswordAuthenticationToken upToken =
            new UsernamePasswordAuthenticationToken(userName, decodePassword);
    final Authentication authentication = authenticationManager.authenticate(upToken);
    SecurityContextHolder.getContext().setAuthentication(authentication);
    return token;
  }

  /**
   * 读取私钥文件，将公钥加密的密码配对私钥进行解密
   *
   * @param password
   * @return
   */
  private String decodeRasPwdToPlainText(String password) {
    Resource resource = new ClassPathResource(AuthorizationConstants.PRIVATE_KEY_RESOURCE_PATH);
    try {
      final Path path = Paths.get(resource.getURI());
      final byte[] priKeyBytes = Files.readAllBytes(path);
      PrivateKey privateKey = securityRsaAlgorithm.restorePrivateKey(Base64Utils.decode(priKeyBytes));
      return securityRsaAlgorithm.rsaDecode(privateKey, Base64Utils.decode(password.getBytes(StandardCharsets.UTF_8)));
    } catch (IOException e) {
      log.error("Abnormal error in reading private key file", e);
    }
    return null;
  }

  /**
   * 刷新token
   *
   * @param userName
   * @return
   */
  public String generateRefreshToken(String userName) {
    return this.generationJwtStr(userName);
  }

  /**
   * 生成jwt字符串，过期时间默认为20天
   *
   * @param userName
   * @return
   */
  private String generationJwtStr(String userName) {
    LocalDate expireDate = LocalDate.now().plusDays(20);
    return jwtTokenUtils.generationJwt(userName, expireDate, false);
  }

  /**
   * 注册系统接口用户
   *
   * @return
   */
  @Transactional
  public boolean registerAuthorizePrimary(final AuthPrimary authPrimary) {
    BCryptPasswordEncoder cryptPasswordEncoder = new BCryptPasswordEncoder();
    AuthPrimary registerAuthPrimary = AuthPrimary.builder()
            .password(cryptPasswordEncoder.encode(authPrimary.getPassword()))
            .code(authPrimary.getCode()).userName(authPrimary.getUserName())
            .email(authPrimary.getEmail()).role(AuthorizationConstants.ROLE_USER)
            .createTime(new Date()).build();
    this.authRepository.insert(registerAuthPrimary);
    return true;
  }

  /**
   * 获取用户信息
   *
   * @param userName
   * @param code
   * @return
   */
  public AuthPrimary getAuthorizePrimaryInfo(String userName, String code) {
    final AuthPrimary authPrimary = authRepository.selectOne(
            new QueryWrapper<AuthPrimary>().allEq(new HashMap<>(){{
              put("userName", userName);put("code", code);
            }}));
    Assert.notNull(authPrimary, "controller user info can't get");
    return authPrimary;
  }
}

