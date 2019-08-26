package cn.ruoshy.security.handle;


import cn.ruoshy.security.model.StatusMessage;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 身份验证失败处理
 */
@Component
public class AuthenticationFailureHandlerImpl implements AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException {
        StatusMessage message = new StatusMessage();
        message.setStatus(401);
        if (e instanceof LockedException) {
            message.setMsg("账户被锁定,登录失败!");
        } else if (e instanceof BadCredentialsException) {
            message.setMsg("账户名或密码输入错误,登录失败!");
        } else if (e instanceof DisabledException) {
            message.setMsg("账户被禁用,登录失败!");
        } else if (e instanceof AccountExpiredException) {
            message.setMsg("账户已过期,登录失败!");
        } else {
            message.setMsg("登录失败!");
        }
        message.callback(response);
    }
}