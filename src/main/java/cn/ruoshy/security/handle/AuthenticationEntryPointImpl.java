package cn.ruoshy.security.handle;

import cn.ruoshy.security.model.StatusMessage;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 验证输入点
 */
@Component
public class AuthenticationEntryPointImpl implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException {
        StatusMessage message = new StatusMessage();
        message.setMsg("请求失败,请登录!");
        message.setStatus(403);
        message.callback(response);
    }
}
