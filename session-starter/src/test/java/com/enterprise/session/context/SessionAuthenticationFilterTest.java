package com.enterprise.session.context;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class SessionAuthenticationFilterTest {

    private static final String SESSION_ID = "c83b860d-4581-4246-86d7-e07584bd3bc1";

    private final SessionLookup lookup = mock(SessionLookup.class);
    private final SessionAuthenticationFilter filter = new SessionAuthenticationFilter(lookup, "X-Session-ID");
    private final AtomicReference<Authentication> seenByChain = new AtomicReference<>();
    private final MockFilterChain chain = new MockFilterChain() {
        @Override
        public void doFilter(jakarta.servlet.ServletRequest request, jakarta.servlet.ServletResponse response) {
            seenByChain.set(SecurityContextHolder.getContext().getAuthentication());
        }
    };

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void validSessionBecomesAuthenticationWithPermissionsAndRoles() throws Exception {
        when(lookup.find(SESSION_ID)).thenReturn(Optional.of(new SessionContext(SESSION_ID, "mario.rossi", null,
                "TENANT_A", List.of("DOCTOR"), List.of("patient:read"), null, Instant.now().plusSeconds(60).toString())));

        filter.doFilter(request(SESSION_ID), new MockHttpServletResponse(), chain);

        Authentication auth = seenByChain.get();
        assertThat(auth.getName()).isEqualTo("mario.rossi");
        assertThat(auth.getAuthorities()).extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("patient:read", "ROLE_DOCTOR");
        assertThat(((SessionContext) auth.getPrincipal()).tenantId()).isEqualTo("TENANT_A");
        assertThat(auth.getCredentials()).isNull();
    }

    @Test
    void unknownSessionLeavesRequestUnauthenticated() throws Exception {
        when(lookup.find(SESSION_ID)).thenReturn(Optional.empty());

        filter.doFilter(request(SESSION_ID), new MockHttpServletResponse(), chain);

        assertThat(seenByChain.get()).isNull();
    }

    @Test
    void missingHeaderSkipsLookup() throws Exception {
        filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), chain);

        verifyNoInteractions(lookup);
        assertThat(seenByChain.get()).isNull();
    }

    @Test
    void unavailableStoreAnswers503WithoutCallingTheChain() throws Exception {
        when(lookup.find(SESSION_ID)).thenThrow(new SessionStoreUnavailableException(new RuntimeException("down")));
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<Boolean> chainCalled = new AtomicReference<>(false);

        filter.doFilter(request(SESSION_ID), response, (req, res) -> chainCalled.set(true));

        assertThat(response.getStatus()).isEqualTo(503);
        assertThat(chainCalled.get()).isFalse();
    }

    private static MockHttpServletRequest request(String sessionId) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Session-ID", sessionId);
        return request;
    }
}
