package com.logicwarez.authz.session;

import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.data.redis.serializer.SerializationException;

/**
 * Serializzazione Java degli attributi di sessione su Redis, come quella predefinita di Spring Session, ma un
 * attributo illeggibile (classe rinominata o con un altro serialVersionUID, scritto da un'altra versione
 * dell'applicazione) vale null invece di far fallire la richiesta con 500. Spring Session scarta gli attributi
 * null: senza {@link SessionContext} la sessione conta come assente (401, o un nuovo login su /bff/login).
 */
public class TolerantSessionSerializer implements RedisSerializer<Object> {

    private static final Logger log = LoggerFactory.getLogger(TolerantSessionSerializer.class);

    private final JdkSerializationRedisSerializer delegate;
    private final AtomicBoolean warned = new AtomicBoolean();

    public TolerantSessionSerializer(ClassLoader classLoader) {
        this.delegate = new JdkSerializationRedisSerializer(classLoader);
    }

    @Override
    public byte[] serialize(Object value) {
        return delegate.serialize(value);
    }

    @Override
    public Object deserialize(byte[] bytes) {
        try {
            return delegate.deserialize(bytes);
        } catch (SerializationException e) {
            // Un attributo vecchio resta in Redis fino alla scadenza della sessione: si avvisa una volta sola
            if (warned.compareAndSet(false, true)) {
                log.warn("Attributo di sessione illeggibile, ignorato (scritto da un'altra versione?): {}",
                        e.getMostSpecificCause().toString());
            } else {
                log.debug("Attributo di sessione illeggibile, ignorato: {}", e.getMostSpecificCause().toString());
            }
            return null;
        }
    }
}
