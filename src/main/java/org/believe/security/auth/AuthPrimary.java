package org.believe.security.auth;

import lombok.Builder;
import lombok.Data;

import javax.validation.constraints.NotBlank;
import java.util.Date;

@Data
@Builder
public class AuthPrimary {

  /**
   * id
   */
  private Long id;

  /**
   * 角色
   */
  private String role;

  /**
   * 用户名
   */
  @NotBlank
  private String userName;

  /**
   * 密码
   */
  @NotBlank
  private String password;

  /**
   * 创建时间
   */
  private Date createTime;

  /**
   * 状态
   */
  private String status;

  /**
   * 邮箱
   */
  @NotBlank
  private String email;

  /**
   * 代码，用于额外的身份验证
   */
  @NotBlank
  private String code;
}
