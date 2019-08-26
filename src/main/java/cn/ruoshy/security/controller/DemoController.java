package cn.ruoshy.security.controller;

import cn.ruoshy.security.enhance.EnhanceAuthentication;
import cn.ruoshy.security.handle.session.GlobalSessionContext;
import com.alibaba.fastjson.JSON;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import javax.servlet.http.HttpSession;

@RestController
public class DemoController {

    @RequestMapping("/index")
    public String index() {
        return "Spring Security";
    }

    @RequestMapping("/book")
    public String book() {
        return "Book";
    }

    @Resource
    private GlobalSessionContext globalSessionContext;

    @RequestMapping("/delrole")
    public boolean delRole(Integer id, String role) {
        HttpSession session = globalSessionContext.getSessionByUserId(id);
        boolean flag = false;
        if (session != null) {
            // TODO 删除数据库角色

            // 获得Spring Security上下文
            SecurityContextImpl securityContextImpl = (SecurityContextImpl) session.getAttribute("SPRING_SECURITY_CONTEXT");
            // 使用自定义身份验证继承Authentication类实现角色增删功能
            EnhanceAuthentication auth = new EnhanceAuthentication(securityContextImpl.getAuthentication());
            auth.delRole("ROLE_" + role);
            securityContextImpl.setAuthentication(auth);
            flag = true;
        }
        return flag;
    }
}