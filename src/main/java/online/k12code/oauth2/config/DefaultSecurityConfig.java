package online.k12code.oauth2.config;

import online.k12code.oauth2.utils.SecurityUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.parameters.P;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Collection;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author Carl
 * @since 1.0.0
 */
@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class DefaultSecurityConfig {
    /**
     * 配置认证相关的过滤器
     *
     * @param httpSecurity
     * @return
     * @throws Exception
     */
    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
        // 配置授权规则
        httpSecurity.authorizeHttpRequests((authorize) -> authorize
                        // 允许所有用户访问静态资源和登录页面
                        .requestMatchers("/assets/**", "/webjars/**", "/login").permitAll()
                        .anyRequest().authenticated()
                )
                // 设置自定义登录页面
                .formLogin(formLogin -> formLogin.loginPage("/login"))
                // 配置资源服务器使用JWT进行验证，接受用户信息和或客户端注册的访问令牌，
                // 如果想让当前服务作为一个资源服务，就需要配置这个使他能有解析token的能力
                // 而authorizationServerSecurityFilterChain过滤链中就不需要添加这个命令了
                .oauth2ResourceServer((resourceServer) -> resourceServer
                        .jwt(Customizer.withDefaults())
                        .accessDeniedHandler(SecurityUtils::exceptionHandler) // 添加自定义异常处理
                        .authenticationEntryPoint(SecurityUtils::exceptionHandler));

        return httpSecurity.build();
    }

    /**
     * 先暂时配置一个基于内存的用户，框架在用户认证会默认调用
     * {@link UserDetailsService#loadUserByUsername(String)} 方法根据
     * 账号查询用户信息，一般是重写该方法实现自己的逻辑
     *
     * @param passwordEncoder
     * @return
     */
    @Bean
    public UserDetailsService users(PasswordEncoder passwordEncoder) {
        UserDetails build = User.withUsername("admin")
                .password(passwordEncoder.encode("123456"))
                .roles("admin", "normal", "unAuthentication")
                .authorities("app", "web", "/test2", "/test3")
                .build();
        return new InMemoryUserDetailsManager(build);
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> oAuth2TokenCustomizer() {
        return context -> {
            // 检查登录用户信息是不是UserDetails, 排除没有用户参与的流程
            if (context.getPrincipal().getPrincipal() instanceof UserDetails user) {
                // 获取申请的scopes
                Set<String> authorizedScopes = context.getAuthorizedScopes();
                // 获取用户的权限
                Collection<? extends GrantedAuthority> authorities = user.getAuthorities();
                // 提取权限并转化为字符串
                Set<String> collect = Optional.ofNullable(authorities)
                        .orElse(Collections.emptyList())
                        .stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toSet());
                // 合并授权信息
                collect.addAll(authorizedScopes);
                // 将授权信息放入jwt的claims中
                JwtClaimsSet.Builder claims = context.getClaims();
                claims.claim("authorities", collect);
                // 还可以自定义其他内容
                System.out.println(claims);
            }
        };
    }

}
