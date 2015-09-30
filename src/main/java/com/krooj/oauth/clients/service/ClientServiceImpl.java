package com.krooj.oauth.clients.service;

import com.krooj.oauth.clients.datamapper.ClientDataMapper;
import com.krooj.oauth.clients.domain.Client;
import com.krooj.oauth.common.util.InputValidationUtils;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Default implementation of the {@link ClientService}
 */
@Service
@Log4j2
public class ClientServiceImpl implements ClientService {

    private ClientDataMapper clientDataMapper;

    @Autowired
    public ClientServiceImpl(ClientDataMapper clientDataMapper) {
        this.clientDataMapper = clientDataMapper;
    }

    @Override
    public Client retrieveClientById(String clientId) {
        InputValidationUtils.assertHasText(clientId, "error.clientid.empty");
        return clientDataMapper.retrieveClientById(clientId);
    }

    @Override
    public UserDetails loadUserByUsername(String clientId) throws UsernameNotFoundException {
        return retrieveClientById(clientId);
    }
}
