package org.believe.http;

import lombok.Data;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Data
public final class BusinessResponse {

  /**
   * 状态码
   */
  private Integer code;

  /**
   * 状态码附加的消息
   */
  private String codeResult;

  /**
   * 返回自定义消息
   */
  private String message;

  /**
   * 附带的数据
   */
  private Object data;

  /**
   * 预留字段
   */
  private Object ext;

  /**
   * 系统业务接口的响应消息
   */
  public static Map<Integer, String> businessResult = new ConcurrentHashMap<Integer, String>() {{
    put(BusinessResult.USER_NOT_FOUND.code(), "用户未找到");
    put(BusinessResult.PASSWORD_BAD.code(), "密码错误");
    put(BusinessResult.CHECK_CODE_BAD.code(), "验证码验证失败");
    put(BusinessResult.ACCOUNT_PASSWORD_ERR.code(), "账号密码错误");
    put(BusinessResult.LOGIN_SUCCESS.code(), "登陆成功");
    put(BusinessResult.USER_NAME_NOT_UNIQUE.code(), "用户名已被使用");
    put(BusinessResult.REGISTER_SUCCESS.code(), "注册成功");
    put(BusinessResult.EMAIL_SEND_SUCCESS.code(), "邮件发送成功");
    put(BusinessResult.CHANGE_PASSWORD_SUCCESS.code(), "修改密码成功");
    put(BusinessResult.CHANGE_PASSWORD_VOUCHER_INVALID.code(), "修改密码的验证凭证无效");
    put(BusinessResult.OLD_PASSWORD_INCONSISTENT.code(), "旧密码不一致");
    put(BusinessResult.TOW_PASSWORDS_INCONSISTENT.code(), "两次密码不一致");
    put(BusinessResult.LINK_EXPIRATION_TIME_HAS_EXPIRED.code(), "链接已经过期");
    put(BusinessResult.VOUCHER_INVALID.code(), "刷新token必须的凭证失效");
    put(BusinessResult.NO_RIGHT_TO_ACCESS.code(), "没有权利访问");
    put(BusinessResult.LOGIN_STATUS_EXPIRED.code(), "登录状态已过期");
    put(BusinessResult.LOGIN_INFO_NOT_FOUND.code(), "登录信息未找到");
    put(BusinessResult.INTERFACE_ACCESS_TIMES_EXCEEDED_LIMIT.code(), "接口访问次数超出限制");
    put(BusinessResult.ARB_COMMISSION_TOKEN_NOT_FOUND.code(), "仲裁委接口访问凭证未找到");
    put(BusinessResult.SIMPLE_SUCCESS.code(), BusinessResult.SIMPLE_SUCCESS.des());
    put(BusinessResult.SIMPLE_FAIL.code(), BusinessResult.SIMPLE_FAIL.des());
  }};

  public BusinessResponse(Integer code, String codeResult) {
    this.code = code;
    this.codeResult = codeResult;
  }

  private BusinessResponse(Integer code, String codeResult, Object data) {
    this.code = code;
    this.codeResult = codeResult;
    this.data = data;
  }

  public BusinessResponse(Integer code, String codeResult, Object data, Object ext) {
    this.code = code;
    this.codeResult = codeResult;
    this.data = data;
    this.ext = ext;
  }

  private BusinessResponse(Integer code, String codeResult, String message) {
    this.code = code;
    this.codeResult = codeResult;
    this.message = message;
  }

  private BusinessResponse(Integer code, String codeResult, String message, Object data) {
    this.code = code;
    this.codeResult = codeResult;
    this.message = message;
    this.data = data;
  }

  private BusinessResponse(Integer code, String codeResult, String message, Object data, Object ext) {
    this.code = code;
    this.codeResult = codeResult;
    this.message = message;
    this.data = data;
    this.ext = ext;
  }

  /**
   * 根据状态码获取返回的消息
   *
   * @param code 状态码
   * @return 返回消息结构体
   */
  public static BusinessResponse resultEntity(Integer code) {
    return new BusinessResponse(code, businessResult.get(code));
  }

  /**
   * 状态码加自定义消息
   *
   * @param code    状态码
   * @param message 自定义消息
   * @return 返回消息结构体
   */
  public static BusinessResponse resultEntity(Integer code, String message) {
    return new BusinessResponse(code, businessResult.get(code), message);
  }

  /**
   * 状态码加数据
   *
   * @param code
   * @param data
   * @return
   */
  public static BusinessResponse resultEntity(Integer code, Object data) {
    return new BusinessResponse(code, businessResult.get(code), data);
  }

  /**
   * 状态码加自定义消息加返回数据
   *
   * @param code    状态码
   * @param message 自定义消息
   * @param data    返回数据
   * @return 返回消息结构体
   */
  public static BusinessResponse resultEntity(Integer code, String message, Object data) {
    return new BusinessResponse(code, businessResult.get(code), message, data);
  }

  /**
   * 状态码加自定义消息加返回数据加预留字段数据
   *
   * @param code    状态码
   * @param message 自定义消息
   * @param data    返回数据
   * @param ext     预留字段数据
   * @return 返回消息结构体
   */
  public static BusinessResponse resultEntity(Integer code, String message, Object data, Object ext) {
    return new BusinessResponse(code, businessResult.get(code), message, data, ext);
  }

  /**
   * 返回简单的成功提示
   *
   * @return 返回消息结构体
   */
  public static BusinessResponse successResult() {
    return new BusinessResponse(
            BusinessResult.SIMPLE_SUCCESS.code(),
            BusinessResult.SIMPLE_SUCCESS.des()
    );
  }

  /**
   * 返回简单的提示和自定义消息
   *
   * @param message 需要返回的消息
   * @return 返回消息结构体
   */
  public static BusinessResponse successResult(String message) {
    return new BusinessResponse(
            BusinessResult.SIMPLE_SUCCESS.code(), BusinessResult.SIMPLE_SUCCESS.des(),
            message
    );
  }

  /**
   * 返回简单的提示加数据
   *
   * @param data 需要返回的数据
   * @return 返回消息结构体
   */
  public static BusinessResponse successResult(Object data) {
    return new BusinessResponse(BusinessResult.SIMPLE_SUCCESS.code(), BusinessResult.SIMPLE_SUCCESS.des(), data);
  }


  /**
   * 返回简单的提示加数据加自定义消息
   *
   * @param message 自定义的消息
   * @param data    需要返回的数据
   * @return 返回消息结构体
   */
  public static BusinessResponse successResult(String message, Object data) {
    return new BusinessResponse(BusinessResult.SIMPLE_SUCCESS.code(), BusinessResult.SIMPLE_SUCCESS.des(), message, data);
  }

  /**
   * 返回数据和额外数据
   */
  public static BusinessResponse successResult(Object data, Object extData) {
    return new BusinessResponse(BusinessResult.SIMPLE_SUCCESS.code(), BusinessResult.SIMPLE_SUCCESS.des(), data, extData);
  }

  /**
   * 返回简单的错误提示
   *
   * @return 返回消息结构体
   */
  public static BusinessResponse failResult() {
    return new BusinessResponse(
            BusinessResult.SIMPLE_FAIL.code(),
            BusinessResult.SIMPLE_FAIL.des()
    );
  }

  /**
   * 返回简单的错误提示加自定义消息，错误提示
   * 不返回实体数据，只返回提示消息
   *
   * @return 返回消息结构体
   */
  public static BusinessResponse failResult(String message) {
    return new BusinessResponse(
            BusinessResult.SIMPLE_FAIL.code(),
            BusinessResult.SIMPLE_FAIL.des(),
            message
    );
  }

  /**
   * 返回简单的错误提示加自定义消息，错误提示
   * 不返回实体数据，只返回提示消息
   *
   * @return 返回消息结构体
   */
  public static BusinessResponse failResult(Object data) {
    return new BusinessResponse(
            BusinessResult.SIMPLE_FAIL.code(),
            BusinessResult.SIMPLE_FAIL.des(),
            data
    );
  }


  /**
   * 从业务异常中根据code获取异常信息
   *
   * @param code
   * @return
   */
  public static BusinessResponse failResult(int code) {
    return new BusinessResponse(
            code,
            businessResult.get(code)
    );
  }

  /**
   * 状态+异常消息
   *
   * @param code
   * @param message
   * @return
   */
  public static BusinessResponse failResult(int code, String message) {
    return new BusinessResponse(
            code,
            message
    );
  }


}
