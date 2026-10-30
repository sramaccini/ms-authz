package com.enterprise.session.context;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.StringRedisTemplate;
import tools.jackson.databind.json.JsonMapper;

/** Registra il lookup della sessione; il collegamento alla sicurezza si fa con {@link SessionContextConfigurer}. */
@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableConfigurationProperties(SessionContextProperties.class)
public class SessionContextAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    SessionLookup sessionLookup(StringRedisTemplate redis, ObjectProvider<JsonMapper> jsonMapper,
                                SessionContextProperties properties) {
        return new SessionLookup(redis, jsonMapper.getIfAvailable(() -> JsonMapper.builder().build()), properties);
    }
}
