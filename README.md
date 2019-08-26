## 概述
&emsp;&emsp;Spring Security是一个功能强大且可高度自定义的身份验证和访问控制框架。专注于为Java应用程序提供身份验证和授权的框架。与所有Spring项目一样，Spring Security的真正强大之处在于它可以轻松扩展以满足自定义要求。

## 基本环境搭建
创建一个Spring Boot Web项目在pom.xml中添加spring-boot-starter-security依赖即可
```xml
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
```
添加完成后项目中的所有资源都会被保护起来

添加一个简单的接口
```java
@RestController
public class DemoController {

    @RequestMapping("/index")
    public String index() {
        return "Spring Security";
    }

}
```

启动成功后在浏览器中访问 /index 接口会自动跳转到登录页面，登录页面是由Spring security提供的，如图所示。

![login.png](https://upload-images.jianshu.io/upload_images/18713780-e182d21ef5c3e5a7.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

默认的用户名是：user，默认的登录密码是在每次启动项目时随机生成的，可在项目启动日志中查看。

![password.png](https://upload-images.jianshu.io/upload_images/18713780-9ced3d58ba9c99ce.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

登录成功后就可以正常访问接口了。

## 配置用户名密码
当对默认的用户名和密码不满意时可在配置文件中进行配置，如下：
```yaml
spring:
  security:
    user:
      roles: admin
      name: cwc
      password: 123456
```
登录成功后用户还会具有一个角色——admin

## 基于内存的认证
我们也可以自定义类继承WebSecurityConfigurerAdapter，实现对Spring Security更多的自定义配置，例如基于内存的认证，如下：
```
@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * @return 密码编码器
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
    /**
     * @param auth 身份验证管理器
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user")
                .password("123456")
                .roles("admin")
                .and()
                .withUser("cwc")
                .password("123456")
                .roles("dba");
    }

}
```
Spring Security 5.x 中引入了多种密码加密方式必须指定一种，当前密码编码器使用的是 NoOpPasswordEncoder，即不对密码进行加密。

## 基于数据库的认证
由于基于内存的认证是定义在内存中的，在一般情况下用户的基本信息以及角色等都是存储在数据库中的，因此需要从数据库获取数据进行的认证和授权。

首先需要设计一个基本的用户角色表，分别是用户表、角色表以及用户角色关联表

![table.png](https://upload-images.jianshu.io/upload_images/18713780-d8d1955de8d0ac16.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

![user.png](https://upload-images.jianshu.io/upload_images/18713780-76eecf09a5fae762.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

###### 角色名有一个默认的前缀 ROLE_

数据库的配置以及表的实体类这里就不演示了，主要是在User 实体类中除了基本的geter/seter 还需要实现接口UserDetails
```java
public class User implements UserDetails {
    private Integer id;
    private String username;
    private String password;
    private Boolean enabled;
    private Boolean locked;
    private List<Role> roles;
 
    /**
     * 获取当前用户对象所具有的角色信息
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        for (Role role : roles) {
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        }
        return authorities;
    }

    /**
     * 当前账户是否未过期
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * 当前账户是否未锁定
     */
    @Override
    public boolean isAccountNonLocked() {
        return !locked;
    }

    /**
     * 当前账户密码是否未过期
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * 账户是否可用
     */
    @Override
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public String getPassword() {
        return password;
    }

    // 省略 getter/setter
}
```
#### 创建UserService
```java
@Service
public class UserService implements UserDetailsService {
    @Resource
    private UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userMapper.loadUserByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException("账户不存在");
        }
        user.setRoles(userMapper.getRoleByUId(user.getId()));
        return user;
    }
}
```
在上面自定义的 WebSecurityConfig 类中重写 configure(AuthenticationManagerBuilder auth)方法。
```
    /**
     * @return 密码编码器
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // 用户详细信息服务
    @Resource
    private UserService userService;

    /**
     * @param auth 身份验证管理器
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userService);
    }
```
由于数据库中用户密码是通过BCryptPasswordEncoder类加密过的所以以上密码编码器已经改为BCryptPasswordEncoder。
完成以上配置后，重启项目就可以使用保存在数据库中的用户名和密码进行登录并根据用户具备的角色进行授权。



## 角色管理以及请求处理

目前虽然已经可以实现认证功能，但是受保护的资源都是默认的无法根据实际情况进行角色管理，若需要实现这些功能可在上面自定义的 WebSecurityConfig 类中重写 configure(HttpSecurity http) 方法。
```java
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
                .antMatchers("/book/**").hasRole("admin")
                // 访问 /brandlist/** 接口的请求必须具备 dba 角色
                .antMatchers("/brandlist/**").hasRole("dba")
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
                .authenticationEntryPoint(authenticationEntryPoint);
    }
```
为了使代码更具可读性可自定义了处理类来实现以下接口：
- AuthenticationSuccessHandler（登录成功处理）
- AuthenticationFailureHandler（登录失败处理）
- LogoutHandler（注销处理）
- AccessDeniedHandler（访问拒绝处理）
- AuthenticationEntryPoint（身份验证入口点失败处理）

源码如下：
##### AuthenticationSuccessHandler
```java
@Component
public class AuthenticationSuccessHandlerImpl implements AuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        StatusMessage message = new StatusMessage();
        message.setMsg("登录成功!");
        message.setStatus(200);
        message.callback(response);
    }
}
```

##### AuthenticationFailureHandler
```java
@Component
public class AuthenticationFailureHandlerImpl implements AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
        StatusMessage message = new StatusMessage();
        message.setStatus(401);
        if (e instanceof LockedException) {
            message.setMsg("账户被锁定,登录失败!");
        } else if (e instanceof BadCredentialsException) {
            message.setMsg("账户名或密码输入错误,登录失败!");
        } else if (e instanceof DisabledException) {
            message.setMsg("账户被禁用,登录失败!");
        } else if (e instanceof AccountExpiredException) {
            message.setMsg("账户已过期,登录失败!");
        } else {
            message.setMsg("登录失败!");
        }
        message.callback(response);
    }
}
```

##### LogoutHandler
```java
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
```

##### AccessDeniedHandler
```java
@Component
public class AccessDeniedHandlerImpl implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException e) throws IOException, ServletException {
        StatusMessage message = new StatusMessage();
        message.setMsg("权限不足!");
        message.setStatus(403);
        message.callback(response);
    }
}
```

##### AuthenticationEntryPoint
```java
@Component
public class AuthenticationEntryPointImpl implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
        StatusMessage message = new StatusMessage();
        message.setMsg("请求失败,请登录!");
        message.setStatus(403);
        message.callback(response);
    }
}
```
#### 接口返回如下：

![login-1.png](https://upload-images.jianshu.io/upload_images/18713780-fc6eee2caf459eee.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

![failure.png](https://upload-images.jianshu.io/upload_images/18713780-0c60401356a90337.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

![logout.png](https://upload-images.jianshu.io/upload_images/18713780-9869d6c7123657e3.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

![denied.png](https://upload-images.jianshu.io/upload_images/18713780-17dd7d18b6c38361.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

![admin-api.png](https://upload-images.jianshu.io/upload_images/18713780-3984530f3f751029.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

![api-data.png](https://upload-images.jianshu.io/upload_images/18713780-39dac3582e27946b.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)