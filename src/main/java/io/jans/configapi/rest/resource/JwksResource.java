/*
 * Janssen Project software is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2020, Janssen Project
 */

package io.jans.configapi.rest.resource;

import com.github.fge.jsonpatch.JsonPatchException;
import io.jans.as.model.config.Conf;
import io.jans.as.model.config.WebKeysConfiguration;
import io.jans.as.model.jwk.JSONWebKey;
import io.jans.configapi.filters.ProtectedApi;
import io.jans.configapi.service.ConfigurationService;
import io.jans.configapi.util.ApiAccessConstants;
import io.jans.configapi.util.ApiConstants;
import io.jans.configapi.util.Jackson;

import javax.inject.Inject;
import javax.validation.constraints.NotNull;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;

import org.slf4j.Logger;

/**
 * @author Yuriy Zabrovarnyy
 */
@Path(ApiConstants.CONFIG + ApiConstants.JWKS)
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class JwksResource extends BaseResource {
    
    @Inject
    Logger log;

    @Inject
    ConfigurationService configurationService;

    @GET
    @ProtectedApi(scopes = { ApiAccessConstants.JWKS_READ_ACCESS })
    public Response get() {
        final String json = configurationService.findConf().getWebKeys().toString();
        return Response.ok(json).build();
    }

    @PUT
    @ProtectedApi(scopes = { ApiAccessConstants.JWKS_WRITE_ACCESS })
    public Response put(WebKeysConfiguration webkeys) {
        log.debug("JWKS details to be updated - webkeys = "+webkeys);
        final Conf conf = configurationService.findConf();
        conf.setWebKeys(webkeys);
        configurationService.merge(conf);
        final String json = configurationService.findConf().getWebKeys().toString();
        return Response.ok(json).build();
    }

    @PATCH
    @Consumes(MediaType.APPLICATION_JSON_PATCH_JSON)
    @ProtectedApi(scopes = { ApiAccessConstants.JWKS_WRITE_ACCESS })
    public Response patch(String requestString) throws JsonPatchException, IOException {
        log.debug("JWKS details to be patched - requestString = "+requestString);
        final Conf conf = configurationService.findConf();
        WebKeysConfiguration webKeys = conf.getWebKeys();
        webKeys = Jackson.applyPatch(requestString, webKeys);
        conf.setWebKeys(webKeys);
        configurationService.merge(conf);
        final String json = configurationService.findConf().getWebKeys().toString();
        return Response.ok(json).build();
    }
    
    @POST
    @ProtectedApi(scopes = { ApiAccessConstants.JWKS_WRITE_ACCESS })
    @Path(ApiConstants.KEY_PATH)
    public Response getKeyById(@NotNull JSONWebKey jwk) {
        log.debug("Adds a new Key to the JWKS = "+jwk); 
        Conf conf = configurationService.findConf();
        WebKeysConfiguration webkeys = configurationService.findConf().getWebKeys();
        log.debug("\n\n WebKeysConfiguration before addding new key =" + webkeys.toString());
        webkeys.getKeys().add(jwk);
        conf.setWebKeys(webkeys);
        configurationService.merge(conf);
        webkeys = configurationService.findConf().getWebKeys();
        log.debug("\n\n WebKeysConfiguration after addding new key =" + webkeys.toString());
        final String json = configurationService.findConf().getWebKeys().getKey(jwk.getKid()).toString();
        return Response.ok(json).build();
    }
    
    @GET
    @ProtectedApi(scopes = { ApiAccessConstants.JWKS_READ_ACCESS })
    @Path(ApiConstants.KID)
    public Response getKeyById(@PathParam(ApiConstants.KID) @NotNull String kid) {
        log.debug("Fetch JWK details by kid = "+kid);        
        final String json = configurationService.findConf().getWebKeys().getKey(kid).toString();
        return Response.ok(json).build();
    }
    
    @PATCH
    @Consumes(MediaType.APPLICATION_JSON_PATCH_JSON)
    @ProtectedApi(scopes = { ApiAccessConstants.JWKS_WRITE_ACCESS })
    @Path(ApiConstants.KID)
    public Response patch(@PathParam(ApiConstants.KID) @NotNull String kid, @NotNull String requestString) throws JsonPatchException, IOException {
        log.debug("JWKS details to be patched for kid = "+kid+" ,requestString = "+requestString);
        final Conf conf = configurationService.findConf();
        JSONWebKey jwk = conf.getWebKeys().getKey(kid);
        jwk = Jackson.applyPatch(requestString, jwk);
        log.debug("JWKS details patched - jwk = "+jwk);
        
        conf.getWebKeys().getKeys().removeIf(x -> x.getKid().equals(kid));
        log.debug("\n\n WebKeysConfiguration after removing key new key =" + conf.getWebKeys().getKeys());
        
        conf.getWebKeys().getKeys().add(jwk);
        log.debug("\n\n WebKeysConfiguration after adding patched for key  kid = "+kid+" ,conf.getWebKeys().getKeys() = "+conf.getWebKeys().getKeys());
        configurationService.merge(conf);
        final String json = configurationService.findConf().getWebKeys().toString();
        return Response.ok(json).build();
    }
}
