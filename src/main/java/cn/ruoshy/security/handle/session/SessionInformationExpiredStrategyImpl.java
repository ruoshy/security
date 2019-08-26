package cn.ruoshy.security.handle.session;

import cn.ruoshy.security.model.StatusMessage;
import org.springframework.security.web.session.SessionInformationExpiredEvent;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * 会话信息过期处理
 */
@Component
public class SessionInformationExpiredStrategyImpl implements SessionInformationExpiredStrategy {
    @Override
    public void onExpiredSessionDetected(SessionInformationExpiredEvent sessionInformationExpiredEvent) throws IOException {
        StatusMessage message = new StatusMessage();
        message.setMsg("登录信息过期,可能是由于同一用户尝试多次登录!");
        message.setStatus(200);
        message.callback(sessionInformationExpiredEvent.getResponse());
    }

}