package com.enterprise.session.context;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

/**
 * Autentica la richiesta con l'header X-Session-ID inoltrato dal BFF.
 * Sessione assente o scaduta: la richiesta prosegue non autenticata e Spring Security risponde 401.
 * Redis non raggiungibile: 503 immediato.
 */
public class SessionAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(SessionAuthenticationFilter.class);

    private final SessionLookup lookup;
    private final String headerName;
    private final SecurityContextHolderStrategy contextHolder = SecurityContextHolder.getContextHolderStrategy();

    public SessionAuthenticationFilter(SessionLookup lookup, String headerName) {
        this.lookup = lookup;
        this.headerName = headerName;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String sessionId = request.getHeader(headerName);
        if (sessionId != null) {
            Optional<SessionContext> session;
            try {
                session = lookup.find(sessionId);
            } catch (SessionStoreUnavailableException e) {
                log.error("Session store non raggiungibile: {}", e.getCause().toString());
                response.setStatus(HttpStatus.SERVICE_UNAVAILABLE.value());
                response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
                response.getWriter().write("""
                        {"type":"about:blank","title":"Service Unavailable","status":503,"detail":"Servizio temporaneamente non disponibile"}""");
                return;
            }
            session.ifPresent(s -> {
                SecurityContext context = contextHolder.createEmptyContext();
                context.setAuthentication(new SessionAuthentication(s));
                contextHolder.setContext(context);
            });
        }
        chain.doFilter(request, response);
    }
}
