package com.krooj.oauth.authorization.web;

import com.krooj.oauth.authorization.domain.AuthorizationRequest;
import com.krooj.oauth.authorization.domain.AuthorizationRequestBuilder;
import com.krooj.oauth.common.domain.GrantType;
import com.krooj.oauth.common.exception.OAuthServiceException;
import lombok.extern.log4j.Log4j2;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.util.StreamUtils;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;

/**
 * Created by michaelkuredjian on 9/20/15.
 */
@Log4j2
public class AuthorizationRequestHttpMessageConverter extends AbstractHttpMessageConverter<AuthorizationRequest> {

    @Override
    public List<MediaType> getSupportedMediaTypes() {
        return Collections.singletonList(MediaType.APPLICATION_FORM_URLENCODED);
    }

    @Override
    protected boolean supports(Class<?> clazz) {
        return clazz.isAssignableFrom(AuthorizationRequest.class);
    }

    @Override
    protected AuthorizationRequest readInternal(Class<? extends AuthorizationRequest> clazz, HttpInputMessage inputMessage) throws IOException, HttpMessageNotReadableException {
        try {
            String httpBody = StreamUtils.copyToString(inputMessage.getBody(), StandardCharsets.UTF_8);
            List<NameValuePair> nvps = URLEncodedUtils.parse(httpBody, StandardCharsets.UTF_8);
            AuthorizationRequestBuilder authorizationRequestBuilder = new AuthorizationRequestBuilder();
            for (NameValuePair nvp : nvps) {
                switch (nvp.getName()) {
                    case "grant_type":
                        authorizationRequestBuilder.setGrantType(GrantType.valueOf(nvp.getValue()));
                        break;
                    case "client_id":
                        authorizationRequestBuilder.setClientId(nvp.getValue());
                        break;
                    case "redirect_uri":
                        authorizationRequestBuilder.setRegisteredRedirect(new URI(nvp.getValue()));
                        break;
                    case "state":
                        authorizationRequestBuilder.setState(nvp.getValue());
                        break;
                    default:
                        throw new OAuthServiceException("error.authorization.request.parameter");
                }
            }
            return authorizationRequestBuilder.createAuthorizationRequest();
        } catch (URISyntaxException e) {
            log.error("op=readInternal msg=Couldn't parse authorization request. Bad redirect_uri.");
            throw new OAuthServiceException("error.authorization.request.parameter");
        }
    }

    @Override
    protected void writeInternal(AuthorizationRequest authorizationRequest, HttpOutputMessage outputMessage) throws IOException, HttpMessageNotWritableException {
        throw new UnsupportedOperationException();
    }
}
