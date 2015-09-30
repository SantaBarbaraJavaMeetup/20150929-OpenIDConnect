package com.krooj.oauth.clients.service;

import com.krooj.oauth.clients.domain.Client;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * Service interface for dealing with {@link Client}s
 */
public interface ClientService extends UserDetailsService {

    Client retrieveClientById(String clientId);

}
