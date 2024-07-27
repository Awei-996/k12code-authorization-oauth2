package online.k12code.oauth2.authorization;

import org.springframework.security.core.Transient;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.Map;

/**
 * 设备码模式token
 * 使用 @Transient 注解标记该类，该注解通常用于表示某个字段或类不应被持久化
 *
 * @author Carl
 * @since 1.0.0
 */
@Transient
public class DeviceClientAuthenticationToken extends OAuth2ClientAuthenticationToken {

    /**
     * 定义一个构造函数，接受 clientId, clientAuthenticationMethod, credentials 和 additionalParameters 参数，并调用父类的相应构造函数进行初始化
     *
     * @param clientId
     * @param clientAuthenticationMethod
     * @param credentials
     * @param additionalParameters
     */
    public DeviceClientAuthenticationToken(String clientId, ClientAuthenticationMethod clientAuthenticationMethod, Object credentials, Map<String, Object> additionalParameters) {
        super(clientId, clientAuthenticationMethod, credentials, additionalParameters);
    }

    /**
     * 定义另一个构造函数，接受 registeredClient, clientAuthenticationMethod 和 credentials 参数，并调用父类的相应构造函数进行初始化
     *
     * @param registeredClient
     * @param clientAuthenticationMethod
     * @param credentials
     */
    public DeviceClientAuthenticationToken(RegisteredClient registeredClient, ClientAuthenticationMethod clientAuthenticationMethod, Object credentials) {
        super(registeredClient, clientAuthenticationMethod, credentials);
    }
}
