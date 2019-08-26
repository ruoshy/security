package cn.ruoshy.security.handle.session;

import cn.ruoshy.security.enhance.EnhanceSessionRegistry;
import cn.ruoshy.security.entity.User;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import javax.servlet.http.HttpSession;
import java.util.HashMap;

@Component
public class GlobalSessionContext {
    // 用户id与与会话之间映射
    private final HashMap<Integer, HttpSession> sessionMap = new HashMap<>();

    // 会话注册器
    @Resource
    private EnhanceSessionRegistry enhanceSessionRegistry;

    synchronized void add(HttpSession session) {
        if (session != null) {
            User user = (User) enhanceSessionRegistry.getSessionInformation(session.getId()).getPrincipal();
            if (user != null) {
                sessionMap.put(user.getId(), session);
                System.out.println("添加session成功 " + sessionMap.size() + " ");
            }
        }
    }

    synchronized void delete(HttpSession session) {
        if (session != null) {
            User user = (User) enhanceSessionRegistry.getSessionInformation(session.getId()).getPrincipal();
            if (user != null && user.isLogout()) {
                // 恢复标记使真正退出时可以被删除
                user.setLogout(true);

                sessionMap.remove(user.getId());
                System.out.println("删除session成功 " + sessionMap.size() + " ");
            }
        }
    }

    public HttpSession getSessionByUserId(Integer id) {
        return sessionMap.get(id);
    }
}
