package cn.ruoshy.security.enhance;

import cn.ruoshy.security.entity.User;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * 自定义会话注册器
 */
@Component
public class EnhanceSessionRegistry extends SessionRegistryImpl {

    /**
     * 获得用户Session信息
     *
     * @param user 用户信息
     */
    private List<SessionInformation> getSessionInformationList(User user) {
        // 获取父类会话注册器Session主体
        List<Object> users = this.getAllPrincipals();
        for (Object principal : users) {
            if (principal instanceof User) {
                final User loggedUser = (User) principal;
                if (user.getId().equals(loggedUser.getId())) {
                    // 返回该用户全部Session信息
                    return this.getAllSessions(principal, false);
                }
            }
        }
        return null;
    }

    /**
     * 单点登录
     * 若存在用户已登录对当前登录用户下线
     *
     * @param user 用户信息
     */
    public void invalidateSession(User user) {
        List<SessionInformation> sessionsInfo = this.getSessionInformationList(user);
        if (sessionsInfo != null) {
            for (SessionInformation sessionInformation : sessionsInfo) {
                // 由于账户被顶自定义的全局Session在添加新的Session时会根据用户id覆盖之前的Session
                // 同时之前的Session被系统删除监听器会同步删除新添加的Session会导致全局Session信息丢失
                // 设置logout变量作为标记使全局Session删除时判断是否删除对应session
                User oldUser = (User) sessionInformation.getPrincipal();
                oldUser.setLogout(false);
                // 会话过期
                sessionInformation.expireNow();
            }
        }
    }

}