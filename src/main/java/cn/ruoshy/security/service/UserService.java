package cn.ruoshy.security.service;

import cn.ruoshy.security.entity.User;
import cn.ruoshy.security.enhance.EnhanceSessionRegistry;
import cn.ruoshy.security.mapper.UserMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;

/**
 * 用户登录服务
 */

@Service
public class UserService implements UserDetailsService {
    @Resource
    private UserMapper userMapper;
    @Resource
    private EnhanceSessionRegistry enhanceSessionRegistry;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userMapper.loadUserByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException("账户不存在");
        }
        user.setRoles(userMapper.getRoleByUId(user.getId()));
        enhanceSessionRegistry.invalidateSession(user);
        return user;
    }
}