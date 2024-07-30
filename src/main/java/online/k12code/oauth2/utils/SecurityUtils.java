package online.k12code.oauth2.utils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.BearerTokenErrorCodes;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.net.http.HttpRequest;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @author Carl
 * @since 1.0.0
 */
@Slf4j
public class SecurityUtils {

    public SecurityUtils() {
        throw new UnsupportedOperationException("该类不能实例化");
    }

    public static void exceptionHandler(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
                                        Throwable throwable) {
        Map<String, String> parameters = getErrorParameter(httpServletRequest, httpServletResponse, throwable);
        String wwwAuthenticate = computeWwwAuthenticateHeaderValue(parameters);
        httpServletResponse.addHeader(HttpHeaders.WWW_AUTHENTICATE, wwwAuthenticate);
        try {
            httpServletResponse.setContentType(MediaType.APPLICATION_JSON_VALUE);
            httpServletResponse.getWriter().write(JsonUtils.objectCovertToJson(parameters));
            httpServletResponse.getWriter().flush();
        } catch (IOException ex) {
            log.error("写回错误信息失败", throwable);
        }

    }

    private static Map<String, String> getErrorParameter(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Throwable throwable) {
        Map<String, String> parameters = new LinkedHashMap<>();

        if (httpServletRequest.getUserPrincipal() instanceof AbstractOAuth2TokenAuthenticationToken) {
            // 权限不足
            parameters.put("error", BearerTokenErrorCodes.INSUFFICIENT_SCOPE);
            parameters.put("error_description",
                    "The request requires higher privileges than provided by the access token.");
            parameters.put("error_uri", "https://tools.ietf.org/html/rfc6750#section-3.1");
            httpServletResponse.setStatus(HttpStatus.FORBIDDEN.value());
        }

        if (throwable instanceof OAuth2AuthenticationException authenticationException) {
            //  JWT异常
            OAuth2Error oAuth2Error = authenticationException.getError();
            parameters.put("error", oAuth2Error.getErrorCode());
            if (StringUtils.hasText(oAuth2Error.getUri())) {
                parameters.put("error_uri", oAuth2Error.getUri());
            }
            if (StringUtils.hasText(oAuth2Error.getDescription())) {
                parameters.put("error_description", oAuth2Error.getDescription());
            }
            if (oAuth2Error instanceof BearerTokenError bearerTokenError) {
                if (StringUtils.hasText(bearerTokenError.getScope())) {
                    parameters.put("scope", bearerTokenError.getScope());
                }
                httpServletResponse.setStatus(bearerTokenError.getHttpStatus().value());
            }
        }

        if (throwable instanceof InsufficientAuthenticationException) {
            // 没有携带jwt访问接口，没有客户端认证信息
            parameters.put("error", BearerTokenErrorCodes.INVALID_TOKEN);
            parameters.put("error_description", "Not authorized.");
            parameters.put("error_uri", "https://tools.ietf.org/html/rfc6750#section-3.1");
            httpServletResponse.setStatus(HttpStatus.UNAUTHORIZED.value());
        }
        parameters.put("message",throwable.getMessage());
        return parameters;
    }

    public static String computeWwwAuthenticateHeaderValue(Map<String,String> parameters) {
        StringBuilder wwwAuthenticate = new StringBuilder();
        wwwAuthenticate.append("Bearer");
        if (!parameters.isEmpty()) {
            wwwAuthenticate.append("");
            int i = 0;
            for (Map.Entry<String, String> entry : parameters.entrySet()) {
                wwwAuthenticate.append(entry.getKey()).append("=\"").append(entry.getValue()).append("\"");
                if (i != parameters.size() - 1) {
                    wwwAuthenticate.append(", ");
                }
                i++;
            }
        }
        return wwwAuthenticate.toString();
    }
}
