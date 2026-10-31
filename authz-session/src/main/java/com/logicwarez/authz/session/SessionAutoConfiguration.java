package com.logicwarez.authz.session;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ResourceLoader;
import org.springframework.data.redis.serializer.RedisSerializer;

/** Serializzazione delle sessioni su Redis che non fallisce sugli attributi di un'altra versione. */
@AutoConfiguration
@ConditionalOnClass(RedisSerializer.class)
public class SessionAutoConfiguration {

    /** Nome con cui Spring Session Data Redis cerca la serializzazione degli attributi. */
    public static final String SESSION_SERIALIZER = "springSessionDefaultRedisSerializer";

    @Bean(SESSION_SERIALIZER)
    @ConditionalOnMissingBean(name = SESSION_SERIALIZER)
    RedisSerializer<Object> springSessionDefaultRedisSerializer(ResourceLoader resourceLoader) {
        return new TolerantSessionSerializer(resourceLoader.getClassLoader());
    }
}
