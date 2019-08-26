package cn.ruoshy.security.config;

import cn.ruoshy.security.handle.*;
import cn.ruoshy.security.service.UserService;
import cn.ruoshy.security.enhance.EnhanceSessionRegistry;
import cn.ruoshy.security.handle.session.SessionInformationExpiredStrategyImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.annotation.Resource;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    /**
     * @return 密码编码器
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
//        return NoOpPasswordEncoder.getInstance();
    }

    // 用户登录服务
    @Resource
    private UserService userService;

    /**
     * @param auth 身份验证管理器
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userService);
//        auth.inMemoryAuthentication()
//                .withUser("user")
//                .password("123456")
//                .roles("admin")
//                .and()
//                .withUser("cwc")
//                .password("123456")
//                .roles("dba");
    }

    // 登录成功处理
    @Resource
    private AuthenticationSuccessHandlerImpl authenticationSuccessHandler;
    // 登录失败处理
    @Resource
    private AuthenticationFailureHandlerImpl authenticationFailureHandler;
    // 注销处理
    @Resource
    private LogoutHandlerImpl logoutHandler;
    // 访问拒绝处理
    @Resource
    private AccessDeniedHandlerImpl accessDeniedHandler;
    // 身份验证入口点失败处理
    @Resource
    private AuthenticationEntryPointImpl authenticationEntryPoint;

    /**
     * 单点登录
     */
    // 会话信息过期处理
    @Resource
    private SessionInformationExpiredStrategyImpl sessionInformationExpiredStrategy;
    // 会话注册器
    @Resource
    private EnhanceSessionRegistry enhanceSessionRegistry;

    /**
     * @param http http安全处理
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                // 配置跨域资源共享
                .cors()
                .and()
                // 授权请求
                .authorizeRequests()
                // 访问 /book/** 接口的请求必须具备 admin 角色
                .antMatchers("/index/**").hasRole("admin")
                // 访问 /brandlist/** 接口的请求必须具备 dba 角色
                .antMatchers("/book/**").hasRole("dba")
                // 放行其他接口的请求
                .anyRequest().permitAll()
                .and()
                // 登录接口的Url 可通过发起Post 请求进行登录
                .formLogin().loginProcessingUrl("/login")
                // 登录成功处理
                .successHandler(authenticationSuccessHandler)
                // 登录失败处理
                .failureHandler(authenticationFailureHandler)
                .and()
                // 注销接口 默认Url 为/logout 可自定义
                .logout()
                // 注销处理
                .addLogoutHandler(logoutHandler)
                .and()
                .exceptionHandling()
                // 访问拒绝处理
                .accessDeniedHandler(accessDeniedHandler)
                // 身份验证入口点失败处理
                .authenticationEntryPoint(authenticationEntryPoint)
                .and()
                .sessionManagement()
                .maximumSessions(1)
                // 会话注册器
                .sessionRegistry(enhanceSessionRegistry)
                // 会话信息过期处理
                .expiredSessionStrategy(sessionInformationExpiredStrategy);
    }
}
