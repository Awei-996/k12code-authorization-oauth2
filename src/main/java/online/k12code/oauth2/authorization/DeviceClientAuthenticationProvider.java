package online.k12code.oauth2.authorization;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.util.Objects;

/**
 * 设备码认证提供者
 *
 * @author Carl
 * @since 1.0.0
 */
@Slf4j
@RequiredArgsConstructor
public class DeviceClientAuthenticationProvider implements AuthenticationProvider {

    private final RegisteredClientRepository registeredClientRepository;

    /**
     * 异常说明地址
     */
    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-3.2.1";

    /**
     * 重写 authenticate 方法，进行设备客户端的认证
     *
     * @param authentication
     * @return
     * @throws AuthenticationException
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        // 将传入的 Authentication 对象转换为 DeviceClientAuthenticationToken 类型
        DeviceClientAuthenticationToken deviceClientAuthentication = (DeviceClientAuthenticationToken) authentication;
        // 如果客户端认证方法不是 NONE，则返回 null
        if (!ClientAuthenticationMethod.NONE.equals(deviceClientAuthentication.getClientAuthenticationMethod())) {
            return null;
        }
        // 获取设备客户端的 client_id
        String clientId = deviceClientAuthentication.getPrincipal().toString();
        // 根据 client_id 查找注册的客户端
        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);

        if (Objects.isNull(registeredClient)) {
            throwInvalidClient(OAuth2ParameterNames.CLIENT_ID);
        }

        if (log.isTraceEnabled()) {
            log.trace("Retrieved registered client");
        }

        if (!registeredClient.getClientAuthenticationMethods().contains(deviceClientAuthentication.getClientAuthenticationMethod())) {
            throwInvalidClient("authentication_method");
        }
        if (log.isTraceEnabled()) {
            log.trace("Validated device client authentication parameters");
        }

        // 返回一个新的、经过认证的 DeviceClientAuthenticationToken 对象
        return new DeviceClientAuthenticationToken(registeredClient, deviceClientAuthentication.getClientAuthenticationMethod(), null);
    }

    /**
     *  重写 supports 方法，判断是否支持 DeviceClientAuthenticationToken 类型的认证
     * @param authentication
     * @return
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return DeviceClientAuthenticationToken.class.isAssignableFrom(authentication);
    }

    /**
     * 定义一个私有静态方法 throwInvalidClient，用于抛出无效客户端异常
     * @param parameterName
     */
    private static void throwInvalidClient(String parameterName) {
        OAuth2Error oAuth2Error = new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT, "Device client authentication failed: " + parameterName, ERROR_URI);
        throw new OAuth2AuthenticationException(oAuth2Error);
    }
}
