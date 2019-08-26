package cn.ruoshy.security.handle;

import cn.ruoshy.security.model.StatusMessage;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import org.springframework.security.access.AccessDeniedException;

/**
 * 拒绝访问处理
 */
@Component
public class AccessDeniedHandlerImpl implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException e) throws IOException {
        StatusMessage message = new StatusMessage();
        message.setMsg("权限不足!");
        message.setStatus(403);
        message.callback(response);
    }
}