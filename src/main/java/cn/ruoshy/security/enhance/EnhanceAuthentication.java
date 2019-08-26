package cn.ruoshy.security.enhance;


import cn.ruoshy.security.entity.User;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class EnhanceAuthentication implements Authentication {
    // 身份信息
    private Authentication authentication;
    // 角色信息
    private Collection<? extends GrantedAuthority> authorities;

    public EnhanceAuthentication(Authentication authentication) {
        this.authentication = authentication;
        this.authorities = authentication.getAuthorities();
    }

    public void delRole(String role) {
        User user = (User) getPrincipal();
        user.getRoles().removeIf(r -> r.getName().equals(role));
        authorities = user.getAuthorities();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public Object getCredentials() {
        return authentication.getCredentials();
    }

    @Override
    public Object getDetails() {
        return authentication.getDetails();
    }

    @Override
    public Object getPrincipal() {
        return authentication.getPrincipal();
    }

    @Override
    public boolean isAuthenticated() {
        return authentication.isAuthenticated();
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        authentication.setAuthenticated(isAuthenticated());
    }

    @Override
    public String getName() {
        return authentication.getName();
    }
}
