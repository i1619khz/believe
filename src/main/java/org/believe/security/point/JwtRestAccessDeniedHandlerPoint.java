package org.believe.security.point;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author WangYi
 * @since 2019/6/20
 */
@Component
public class JwtRestAccessDeniedHandlerPoint implements AccessDeniedHandler {
  @Override
  public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException e) throws IOException {
    response.setHeader("Access-Control-Allow-Origin", "*");
    response.sendError(HttpServletResponse.SC_FORBIDDEN, "Forbidden");
  }
}
