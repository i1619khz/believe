package org.believe.security;

import org.believe.security.point.JwtAuthenticationEntryPoint;
import org.believe.security.point.JwtRestAccessDeniedHandlerPoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.annotation.Resource;
import java.util.Collections;

/**
 * @author WangYi
 * @version 1.0
 * @since 2019/2/15
 */
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebAuthorizeConfiguration extends WebSecurityConfigurerAdapter {

  /**
   * 用户详情服务
   */
  @Qualifier("securityUserDetailServiceImpl")
  @Resource
  private UserDetailsService userDetailsService;

  /**
   * Jwt认证入口点，处理401
   */
  @Resource
  private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

  /**
   * jwt认证后的处理，处理访问被拒绝处理程序
   */
  @Resource
  private JwtRestAccessDeniedHandlerPoint jwtRestAccessDeniedHandlerPoint;

  /**
   * 配置身份验证
   *
   * @param authenticationManagerBuilder
   * @throws Exception
   */
  @Autowired
  public void configureAuthentication(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
    authenticationManagerBuilder.userDetailsService(this.userDetailsService).passwordEncoder(passwordEncoder());
  }

  /**
   * 密码编码器
   *
   * @return
   */
  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  /**
   * 身份验证管理器
   *
   * @return
   * @throws Exception
   */
  @Bean(name = BeanIds.AUTHENTICATION_MANAGER)
  @Override
  public AuthenticationManager authenticationManagerBean() throws Exception {
    return super.authenticationManagerBean();
  }

  /**
   * cors跨域请求访问配置
   *
   * @return
   */
  @Bean
  CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.setAllowedOrigins(Collections.singletonList("*"));
    configuration.setAllowedHeaders(Collections.singletonList("*"));
    configuration.setAllowedMethods(Collections.singletonList("*"));
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;
  }

  @Override
  protected void configure(HttpSecurity httpSecurity) throws Exception {
    httpSecurity
            // 由于使用的是JWT，我们这里不需要csrf
            .csrf().disable()

            .exceptionHandling().authenticationEntryPoint(jwtAuthenticationEntryPoint).and()
            .exceptionHandling().accessDeniedHandler(jwtRestAccessDeniedHandlerPoint).and()

            // 基于token，所以不需要session
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()

            .authorizeRequests()
            //.antMatchers(HttpMethod.OPTIONS, "/**").permitAll()

            // 允许对于网站静态资源的无授权访问
            .antMatchers(
                    HttpMethod.GET,
                    "/",
                    "/*.html",
                    "/favicon.ico",
                    "/**/*.html",
                    "/**/*.css",
                    "/**/*.js"
            ).permitAll()
            // 对于获取token的rest api要允许匿名访问
            .antMatchers("/auth/**").permitAll()
            // 除上面外的所有请求全部需要鉴权认证
            .anyRequest().authenticated();

    // 禁用缓存
    httpSecurity.headers().cacheControl();
  }
}
