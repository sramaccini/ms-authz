package com.enterprise.bff.security;

import com.enterprise.bff.TestProperties;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class IamLogoutTest {

    @Test
    void buildsRpInitiatedLogoutUrlWithIdTokenHint() {
        IamLogout logout = new IamLogout(registrations(Map.of("end_session_endpoint", "http://iam.test/logout")),
                TestProperties.bff());

        UriComponents url = UriComponentsBuilder.fromUriString(logout.logoutUrl("eyJ.id.token").block()).build();

        assertThat(url.getHost()).isEqualTo("iam.test");
        assertThat(url.getPath()).isEqualTo("/logout");
        assertThat(url.getQueryParams().getFirst("client_id")).isEqualTo("bff-gateway");
        assertThat(url.getQueryParams().getFirst("id_token_hint")).isEqualTo("eyJ.id.token");
        assertThat(url.getQueryParams().getFirst("post_logout_redirect_uri"))
                .isEqualTo(TestProperties.FRONTEND + "/"); // ':' e '/' sono ammessi nella query (RFC 3986)
    }

    @Test
    void withoutIdTokenTheHintIsOmitted() {
        IamLogout logout = new IamLogout(registrations(Map.of("end_session_endpoint", "http://iam.test/logout")),
                TestProperties.bff());

        assertThat(logout.logoutUrl(null).block()).doesNotContain("id_token_hint");
    }

    @Test
    void withoutEndSessionEndpointGoesBackToTheFrontend() {
        IamLogout logout = new IamLogout(registrations(Map.of()), TestProperties.bff());

        assertThat(logout.logoutUrl("eyJ.id.token").block()).isEqualTo(TestProperties.FRONTEND + "/");
    }

    private static InMemoryReactiveClientRegistrationRepository registrations(Map<String, Object> metadata) {
        return new InMemoryReactiveClientRegistrationRepository(ClientRegistration.withRegistrationId("iam")
                .clientId("bff-gateway")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .authorizationUri("http://iam.test/auth")
                .tokenUri("http://iam.test/token")
                .providerConfigurationMetadata(metadata)
                .build());
    }
}
