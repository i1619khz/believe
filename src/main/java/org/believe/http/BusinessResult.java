package org.believe.http;

public enum BusinessResult {

  USER_NOT_FOUND(800000, "用户未找到"),
  PASSWORD_BAD(800001, "密码错误"),
  CHECK_CODE_BAD(800002, "验证码验证失败"),
  ACCOUNT_PASSWORD_ERR(800003, "账号密码错误"),
  LOGIN_SUCCESS(900000, "登陆成功"),
  REGISTER_SUCCESS(900001, "注册成功"),
  USER_NAME_NOT_UNIQUE(900003, "用户名已被使用"),
  EMAIL_SEND_SUCCESS(900004, "邮件发送成功"),
  CHANGE_PASSWORD_SUCCESS(900005, "修改密码成功"),
  CHANGE_PASSWORD_VOUCHER_INVALID(900006, "修改密码的验证凭证无效"),
  OLD_PASSWORD_INCONSISTENT(900007, "旧密码不一致"),
  TOW_PASSWORDS_INCONSISTENT(900008, "两次密码不一致"),
  LINK_EXPIRATION_TIME_HAS_EXPIRED(900009, "链接已经过期"),
  VOUCHER_INVALID(900010, "刷新token必须的凭证失效"),
  NO_RIGHT_TO_ACCESS(900011, "没有权利访问"),
  LOGIN_STATUS_EXPIRED(900012, "登录状态已过期"),
  LOGIN_INFO_NOT_FOUND(900014, "登录信息未找到"),
  INTERFACE_ACCESS_TIMES_EXCEEDED_LIMIT(900015, "接口访问次数超出限制"),
  ARB_COMMISSION_TOKEN_NOT_FOUND(900016, "仲裁委接口访问凭证未找到"),
  SIMPLE_SUCCESS(200, "success"),
  SIMPLE_FAIL(-1, "fail");

  private Integer code;
  private String des;

  //Interface access times exceeded limit
  BusinessResult(Integer code) {
    this.code = code;
  }

  BusinessResult(Integer code, String des) {
    this.code = code;
    this.des = des;
  }

  public Integer code() {
    return code;
  }

  public String des() {
    return des;
  }
}
