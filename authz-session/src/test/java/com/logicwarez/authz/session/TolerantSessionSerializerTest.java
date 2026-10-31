package com.logicwarez.authz.session;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URL;
import java.net.URLClassLoader;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;

class TolerantSessionSerializerTest {

    private static final SessionContext CONTEXT = new SessionContext("anna.bianchi", "Anna Bianchi",
            "anna@example.org", "TENANT_A", List.of(new SessionContext.Tenant("TENANT_A", "Sede A")),
            List.of("VIEWER"), List.of("demo.item.read"), Instant.EPOCH, Instant.EPOCH.plusSeconds(3600));

    @Test
    void contestoDellaSessioneAndataERitorno() {
        TolerantSessionSerializer serializer = new TolerantSessionSerializer(getClass().getClassLoader());
        assertThat(serializer.deserialize(serializer.serialize(CONTEXT))).isEqualTo(CONTEXT);
    }

    @Test
    void attributoDiUnaClasseCheNonCeVale_null() throws Exception {
        byte[] bytes = new TolerantSessionSerializer(getClass().getClassLoader()).serialize(CONTEXT);
        // Class loader che non vede le classi della libreria: come una sessione scritta prima di un rename
        try (URLClassLoader withoutLibrary = new URLClassLoader(new URL[0], null)) {
            assertThat(new TolerantSessionSerializer(withoutLibrary).deserialize(bytes)).isNull();
        }
    }

    @Test
    void byteIllegibiliValgono_null() {
        TolerantSessionSerializer serializer = new TolerantSessionSerializer(getClass().getClassLoader());
        assertThat(serializer.deserialize(new byte[] {1, 2, 3})).isNull();
    }
}
