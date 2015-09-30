package com.krooj.oauth.clients.datamapper;

import com.krooj.oauth.clients.domain.Client;
import com.krooj.oauth.clients.domain.ClientBuilder;
import com.krooj.oauth.common.domain.GrantType;
import com.krooj.oauth.common.domain.Scopes;
import com.krooj.oauth.common.exception.OAuthServiceException;
import com.krooj.oauth.common.util.InputValidationUtils;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Repository;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Mock implementation of the {@link ClientDataMapper}
 */
@Repository
@Log4j2
public class MockClientDataMapperImpl implements ClientDataMapper {

    private Map<String, Client> mockClients = new ConcurrentHashMap<>();

    public MockClientDataMapperImpl() {
        //Add a mock client
        try {
            Client mockClient = new ClientBuilder()
                    .setClientId("mock")
                    .setClientSecret("secret")
                    .setClientName("mock")
                    .setRegisteredRedirects(new HashSet<>(Arrays.asList(new URI("http://localhost"))))
                    .setAuthorizedGrantType(new HashSet<>(Arrays.asList(GrantType.authorization_code, GrantType.refresh, GrantType.implicit)))
                    .addRole("CLIENT")
                    .setEligibleScopes(new HashSet<>(Arrays.asList(Scopes.openid, Scopes.write)))
                    .createClient();
            mockClients.put(mockClient.getClientId(), mockClient);
        } catch (URISyntaxException e) {
            log.error("op=MockClientDataMapperImpl", e);
        }
    }

    @Override
    public Client retrieveClientById(String clientId) {
        InputValidationUtils.assertHasText(clientId, "error.clientid.empty");
        Client foundClient = mockClients.get(clientId);
        if (foundClient == null) {
            throw new OAuthServiceException("error.client.nonexistent");
        }
        return foundClient;
    }
}
