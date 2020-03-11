package org.believe.security.auth;

import org.believe.http.BusinessResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

/**
 * @author WangYi
 * @version 1.0
 * @since 2019/2/14
 */
@ControllerAdvice
@RestController
@RequestMapping("/auth")
public class AuthController {

  @Autowired
  private AuthService authService;

  @PostMapping(value = "/login", headers = "version=auth/1.0")
  public BusinessResponse login(final String username, final String password) {
    Assert.notNull(username, "username can't be empty");
    Assert.notNull(password, "password can't be empty");
    final String token = authService.loginAndGenerateToken(username, password);
    if (token != null) {
      return BusinessResponse.successResult("验证成功", token);
    } else {
      return BusinessResponse.failResult("验证失败");
    }
  }

  /**
   * 注册基本权限的账号
   *
   * @return
   */
  @PostMapping(value = "/register", headers = "version=auth/1.0")
  public BusinessResponse register(@Valid @RequestBody AuthPrimary authPrimary) {
    Assert.notNull(authPrimary, "auth primary object can't be null");
    final boolean registerResult = authService.registerAuthorizePrimary(authPrimary);
    return registerResult ? BusinessResponse.successResult("api user register success") :
            BusinessResponse.failResult("api controller user register fail");
  }

  /**
   * 刷新token
   */
  @GetMapping(value = "/refresh", headers = "version=auth/1.0")
  public BusinessResponse refresh(@RequestParam final String userName) {
    Assert.notNull(userName, "userName can't be null");
    String refreshToken = authService.generateRefreshToken(userName);
    return BusinessResponse.successResult("generate token success", refreshToken);
  }

  /**
   * 获取用户信息
   */
  @GetMapping(value = "/user", headers = "version=auth/1.0")
  public BusinessResponse userInfo(@RequestParam final String userName,
                                   @RequestParam final String code) {
    Assert.notNull(userName, "userName can't be null");
    Assert.notNull(code, "code can't be null");
    final AuthPrimary authPrimary = authService.getAuthorizePrimaryInfo(userName, code);
    return BusinessResponse.successResult("api user info get success", authPrimary);
  }

}