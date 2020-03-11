package org.believe.security.defense.xss;

import javax.servlet.*;
import java.io.IOException;

/**
 * XSS过滤
 *
 * @author wangyi
 */
public class XssFilter implements Filter {

  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
          throws IOException, ServletException {
    chain.doFilter(request, response);
  }

  @Override
  public void destroy() {
  }

}