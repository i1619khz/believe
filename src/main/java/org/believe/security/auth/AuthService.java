package org.believe.security.auth;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import lombok.extern.slf4j.Slf4j;
import org.believe.security.AuthorizationConstants;
import org.believe.security.SecurityRsaAlgorithm;
import org.believe.security.jwt.TokenProvider;
import org.believe.toolkit.ClockConverter;
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

@Slf4j
@Component
public class AuthService {

  @Autowired
  private TokenProvider tokenProvider;

  @Autowired
  private ClockConverter clockConverter;

  @Autowired
  private AuthRepository authRepository;

  @Autowired
  private AuthenticationManager authenticationManager;

  @Autowired
  private SecurityRsaAlgorithm securityRsaAlgorithm;

  /**
   * 效验凭证
   *
   * @param userName 账户名
   * @param password 密码
   */
  public String loginAndGenerateToken(String userName, String password) {
    Assert.notNull(userName, "userName can not be null");
    Assert.notNull(password, "password can not be null");
    final Authentication authentication = getAuthentication(userName, password);
    SecurityContextHolder.getContext().setAuthentication(authentication);
    return generationJwtStr(authentication);
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
   * @param userName 账户名
   * @return
   */
  public String generateRefreshToken(String userName, String password) {
    final Authentication authentication = getAuthentication(userName, password);
    return this.generationJwtStr(authentication);
  }

  /**
   * 根据账号密码返回Authentication对象
   */
  private Authentication getAuthentication(String userName, String password) {
    final String decodePassword = decodeRasPwdToPlainText(password);
    UsernamePasswordAuthenticationToken upToken =
            new UsernamePasswordAuthenticationToken(userName, decodePassword);
    return authenticationManager.authenticate(upToken);
  }

  /**
   * 生成jwt字符串，过期时间默认为20天
   *
   * @param authentication 授权对象
   * @return 加密token字符串
   */
  private String generationJwtStr(Authentication authentication) {
    LocalDate expireDate = LocalDate.now().plusDays(20);
    return tokenProvider.createToken(authentication, clockConverter.localDateToDate(expireDate));
  }

  /**
   * 注册系统接口用户
   *
   * @return 注册结果
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
   * @param userName 账户名
   * @param code     唯一识别码
   * @return 用户实体信息
   */
  public AuthPrimary getAuthorizePrimaryInfo(String userName, String code) {
    final AuthPrimary authPrimary = authRepository.selectOne(
            new QueryWrapper<AuthPrimary>()
                    .eq("userName", userName)
                    .eq("code", code));
    Assert.notNull(authPrimary, "controller user info can't get");
    return authPrimary;
  }
}

