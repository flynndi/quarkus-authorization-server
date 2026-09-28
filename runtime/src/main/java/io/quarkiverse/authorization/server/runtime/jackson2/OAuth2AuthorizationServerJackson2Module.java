/*
 * Copyright 2020-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.quarkiverse.authorization.server.runtime.jackson2;

import java.io.Serial;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.Principal;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.cfg.CoercionAction;
import com.fasterxml.jackson.databind.cfg.CoercionInputShape;
import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.type.LogicalType;

import io.quarkiverse.authorization.server.endpoint.OAuth2AuthorizationRequest;
import io.quarkiverse.authorization.server.jose.jws.MacAlgorithm;
import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.oidc.session.SessionInformation;
import io.quarkiverse.authorization.server.settings.OAuth2TokenFormat;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

/**
 * Jackson module for the authorization-server domain types currently persisted by JDBC.
 */
public final class OAuth2AuthorizationServerJackson2Module extends SimpleModule {

    @Serial
    private static final long serialVersionUID = 5274359437281152176L;

    public OAuth2AuthorizationServerJackson2Module() {
        super(OAuth2AuthorizationServerJackson2Module.class.getName(), new Version(1, 0, 0, null, null, null));
    }

    @Override
    public void setupModule(SetupContext context) {
        enableDefaultTyping(context.getOwner());
        ObjectMapper mapper = context.getOwner();
        // Names and roles are text, never numeric/boolean values coerced into strings.
        for (CoercionInputShape shape : List.of(
                CoercionInputShape.Integer,
                CoercionInputShape.Float,
                CoercionInputShape.Boolean)) {
            mapper.coercionConfigFor(LogicalType.Textual).setCoercion(shape, CoercionAction.Fail);
        }
        context.setMixInAnnotations(
                QuarkusSecurityIdentity.class, QuarkusSecurityIdentityMixin.class);
        context.setMixInAnnotations(Principal.class, QuarkusPrincipalMixin.class);
        context.setMixInAnnotations(QuarkusPrincipal.class, QuarkusPrincipalMixin.class);
        context.setMixInAnnotations(Collections.unmodifiableMap(Collections.emptyMap()).getClass(),
                UnmodifiableMapMixin.class);
        context.setMixInAnnotations(Collections.unmodifiableList(Collections.emptyList()).getClass(),
                UnmodifiableListMixin.class);
        context.setMixInAnnotations(Collections.unmodifiableSet(Collections.emptySet()).getClass(),
                UnmodifiableSetMixin.class);
        context.setMixInAnnotations(HashSet.class, HashSetMixin.class);
        context.setMixInAnnotations(LinkedHashSet.class, HashSetMixin.class);
        context.setMixInAnnotations(Duration.class, DurationMixin.class);
        context.setMixInAnnotations(OAuth2AuthorizationRequest.class, OAuth2AuthorizationRequestMixin.class);
        context.setMixInAnnotations(AuthorizationGrantType.class, StringValueMixin.class);
        context.setMixInAnnotations(ClientAuthenticationMethod.class, StringValueMixin.class);
        context.setMixInAnnotations(SignatureAlgorithm.class, JwsAlgorithmMixin.class);
        context.setMixInAnnotations(MacAlgorithm.class, JwsAlgorithmMixin.class);
        context.setMixInAnnotations(OAuth2TokenFormat.class, OAuth2TokenFormatMixin.class);
        context.setMixInAnnotations(OAuth2TokenType.class, StringValueMixin.class);
        context.setMixInAnnotations(SessionInformation.class, SessionInformationMixin.class);
        super.setupModule(context);
    }

    private static void enableDefaultTyping(ObjectMapper objectMapper) {
        if (objectMapper.getDeserializationConfig().getDefaultTyper(null) != null) {
            return;
        }
        BasicPolymorphicTypeValidator typeValidator = BasicPolymorphicTypeValidator.builder()
                .allowIfSubType(exactType(QuarkusSecurityIdentity.class))
                .allowIfSubType(exactType(ArrayList.class))
                .allowIfSubType(exactType(List.of().getClass()))
                .allowIfSubType(exactType(List.of("value").getClass()))
                .allowIfSubType(exactType(Map.of().getClass()))
                .allowIfSubType(exactType(Map.of("key", "value").getClass()))
                .allowIfSubType(exactType(HashMap.class))
                .allowIfSubType(exactType(HashSet.class))
                .allowIfSubType(exactType(LinkedHashMap.class))
                .allowIfSubType(exactType(LinkedHashSet.class))
                .allowIfSubType(exactType(Collections.emptyMap().getClass()))
                .allowIfSubType(
                        exactType(
                                Collections.unmodifiableList(Collections.emptyList())
                                        .getClass()))
                .allowIfSubType(exactType(Collections.unmodifiableMap(Map.of()).getClass()))
                .allowIfSubType(
                        exactType(
                                Collections.unmodifiableSet(Collections.emptySet())
                                        .getClass()))
                .allowIfSubType(exactType(BigDecimal.class))
                .allowIfSubType(exactType(BigInteger.class))
                .allowIfSubType(exactType(Duration.class))
                .allowIfSubType(exactType(Instant.class))
                .allowIfSubType(exactType(OAuth2AuthorizationRequest.class))
                .allowIfSubType(exactType(AuthorizationGrantType.class))
                .allowIfSubType(exactType(ClientAuthenticationMethod.class))
                .allowIfSubType(exactType(SignatureAlgorithm.class))
                .allowIfSubType(exactType(MacAlgorithm.class))
                .allowIfSubType(exactType(OAuth2TokenFormat.class))
                .allowIfSubType(exactType(OAuth2TokenType.class))
                .allowIfSubType(exactType(SessionInformation.class))
                .build();
        objectMapper.activateDefaultTyping(
                typeValidator, ObjectMapper.DefaultTyping.NON_FINAL, JsonTypeInfo.As.PROPERTY);
    }

    private static Pattern exactType(Class<?> type) {
        return Pattern.compile(Pattern.quote(type.getName()));
    }
}
