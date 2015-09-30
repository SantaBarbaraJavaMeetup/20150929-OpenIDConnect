package com.krooj.oauth.clients.datamapper;

import com.krooj.oauth.clients.domain.Client;

/**
 * CRUD for a {@link com.krooj.oauth.clients.domain.Client}
 */
public interface ClientDataMapper {

    Client retrieveClientById(String clientId);

}
