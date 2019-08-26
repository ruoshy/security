package cn.ruoshy.security.handle;

import cn.ruoshy.security.model.StatusMessage;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 注销处理
 */
@Component
public class LogoutHandlerImpl implements LogoutHandler {
    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        StatusMessage message = new StatusMessage();
        message.setMsg("注销成功!");
        message.setStatus(403);
        try {
            message.callback(response);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}