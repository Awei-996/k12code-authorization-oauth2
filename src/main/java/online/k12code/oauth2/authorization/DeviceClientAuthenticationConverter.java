package online.k12code.oauth2.authorization;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpMethod;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

/**
 * 获取请求中参数转化为DeviceClientAuthenticationToken
 * 会先执行这个类，将请求转化为合适的AuthenticationProvider，然后在去AuthenticationProvider里面执行
 * @author Carl
 * @since 1.0.0
 */
public final class DeviceClientAuthenticationConverter implements AuthenticationConverter {

    /**
     * 用于匹配设备授权请求
     */
    private final RequestMatcher deviceAuthorizationRequestMatcher;

    /**
     * 用于匹配设备访问令牌请求
     */
    private final RequestMatcher deviceAccessTokenRequestMatcher;

    /**
     * 构造函数，接受一个设备授权端点的URI作为参数
     *
     * @param deviceAuthorizationEndpointUri
     */
    public DeviceClientAuthenticationConverter(String deviceAuthorizationEndpointUri) {
        // 用于检查请求中是否包含client_id 参数
        RequestMatcher clientIdParameterMatcher = request -> request.getParameter(OAuth2ParameterNames.CLIENT_ID) != null;
        // 初始化一个授权匹配，结合路径匹配和client_id 参数检查
        this.deviceAuthorizationRequestMatcher = new AndRequestMatcher(new AntPathRequestMatcher(deviceAuthorizationEndpointUri, HttpMethod.POST.name()), clientIdParameterMatcher);
        // 初始化一个令牌匹配，检查grant_type是否为device_code 并且请求中包含 device_code 和 client_id 参数
        this.deviceAccessTokenRequestMatcher = request -> AuthorizationGrantType.DEVICE_CODE.getValue().equals(request.getParameter(OAuth2ParameterNames.GRANT_TYPE)) &&
                request.getParameter(OAuth2ParameterNames.DEVICE_CODE) != null &&
                request.getParameter(OAuth2ParameterNames.CLIENT_ID) != null;
    }

    /**
     * 重写 convert 方法，将 HttpServletRequest 转换为 Authentication 对象
     * @param request
     * @return
     */
    @Nullable
    @Override
    public Authentication convert(HttpServletRequest request) {

        // 如果请求不匹配 deviceAuthorizationRequestMatcher 或 deviceAccessTokenRequestMatcher，则返回 null
        if (!this.deviceAuthorizationRequestMatcher.matches(request) && !this.deviceAccessTokenRequestMatcher.matches(request)) {
            return null;
        }
        // 获取请求中的 client_id 参数
        String client = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        // 如果 client_id 参数无效或数量不为 1，则抛出 OAuth2AuthenticationException
        if (!StringUtils.hasText(client) || request.getParameterValues(OAuth2ParameterNames.CLIENT_ID).length != 1) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }
        // 返回一个新的 DeviceClientAuthenticationToken 对象，表示认证成功
        return new DeviceClientAuthenticationToken(client, ClientAuthenticationMethod.NONE, null, null);
    }
}
