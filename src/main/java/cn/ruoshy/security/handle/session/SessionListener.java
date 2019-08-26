package cn.ruoshy.security.handle.session;

import javax.annotation.Resource;
import javax.servlet.annotation.WebListener;
import javax.servlet.http.HttpSessionAttributeListener;
import javax.servlet.http.HttpSessionBindingEvent;

@WebListener
public class SessionListener implements HttpSessionAttributeListener {
    @Resource
    private GlobalSessionContext globalSessionContext;

    public void attributeAdded(HttpSessionBindingEvent se) {
        System.out.println("添加session");
        globalSessionContext.add(se.getSession());
    }

    public void attributeRemoved(HttpSessionBindingEvent se) {
        System.out.println("删除session");
        globalSessionContext.delete(se.getSession());
    }

    public void attributeReplaced(HttpSessionBindingEvent se) {
    }
}