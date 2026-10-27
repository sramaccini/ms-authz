package com.enterprise.auth.service;

import com.enterprise.auth.repository.AuthorizationRepository;
import com.enterprise.auth.repository.AuthorizationRepository.ActiveUser;
import com.enterprise.auth.repository.AuthorizationRepository.GrantRow;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthorizationServiceTest {

    private static final UUID USER_ID = UUID.randomUUID();

    private AuthorizationRepository repository;
    private AuthorizationService service;

    @BeforeEach
    void setUp() {
        repository = mock(AuthorizationRepository.class);
        service = new AuthorizationService(repository);
        when(repository.findActiveUser("mario.rossi"))
                .thenReturn(Optional.of(new ActiveUser(USER_ID, "mario.rossi", "mario.rossi@example.org")));
    }

    @Test
    void singleTenantIsSelectedAutomatically() {
        when(repository.findGrants(USER_ID)).thenReturn(List.of(
                new GrantRow("TENANT_A", "DOCTOR", "patient:read"),
                new GrantRow("TENANT_A", "DOCTOR", "patient:write"),
                new GrantRow("TENANT_A", "CUP_OPERATOR", "patient:read")));

        AuthorizationContext ctx = service.resolve("mario.rossi", null);

        assertThat(ctx.tenantId()).isEqualTo("TENANT_A");
        assertThat(ctx.roles()).containsExactly("CUP_OPERATOR", "DOCTOR");
        assertThat(ctx.permissions()).containsExactly("patient:read", "patient:write");
    }

    @Test
    void rolesAreScopedToTheRequestedTenant() {
        when(repository.findGrants(USER_ID)).thenReturn(List.of(
                new GrantRow("TENANT_A", "DOCTOR", "patient:write"),
                new GrantRow("TENANT_B", "CUP_OPERATOR", "booking:manage")));

        AuthorizationContext ctx = service.resolve("mario.rossi", "TENANT_B");

        assertThat(ctx.roles()).containsExactly("CUP_OPERATOR");
        assertThat(ctx.permissions()).containsExactly("booking:manage");
        assertThat(ctx.availableTenants()).containsExactly("TENANT_A", "TENANT_B");
    }

    @Test
    void multipleTenantsWithoutSelectionRequireChoice() {
        when(repository.findGrants(USER_ID)).thenReturn(List.of(
                new GrantRow("TENANT_A", "DOCTOR", null),
                new GrantRow("TENANT_B", "DOCTOR", null)));

        assertThatThrownBy(() -> service.resolve("mario.rossi", null))
                .isInstanceOf(TenantSelectionRequiredException.class);
    }

    @Test
    void tenantWithoutRolesIsRejected() {
        when(repository.findGrants(USER_ID)).thenReturn(List.of(new GrantRow("TENANT_A", "DOCTOR", null)));

        assertThatThrownBy(() -> service.resolve("mario.rossi", "TENANT_X"))
                .isInstanceOf(UserNotAuthorizedException.class);
    }

    @Test
    void unknownOrInactiveUserIsRejected() {
        when(repository.findActiveUser("ghost")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.resolve("ghost", null))
                .isInstanceOf(UserNotAuthorizedException.class);
    }

    @Test
    void roleWithoutPermissionsIsKept() {
        when(repository.findGrants(USER_ID)).thenReturn(List.of(new GrantRow("TENANT_A", "VIEWER", null)));

        AuthorizationContext ctx = service.resolve("mario.rossi", null);

        assertThat(ctx.roles()).containsExactly("VIEWER");
        assertThat(ctx.permissions()).isEmpty();
    }
}
