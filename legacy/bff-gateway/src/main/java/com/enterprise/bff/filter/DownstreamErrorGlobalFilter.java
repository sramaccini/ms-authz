package com.enterprise.bff.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.net.ConnectException;
import java.net.UnknownHostException;
import java.nio.channels.UnresolvedAddressException;

/**
 * Filtro piu' esterno della catena del gateway: traduce i guasti di rete verso i servizi a valle
 * in risposte esplicite invece del 500 generico di default.
 * - 503 se la connessione non si stabilisce (rifiutata, host sconosciuto, connect timeout): il servizio e' giu',
 *   il client puo' riprovare;
 * - 502 se la connessione cade durante lo scambio (reset, chiusura prematura).
 * Il timeout di risposta resta gestito dal gateway (504).
 */
@Component
public class DownstreamErrorGlobalFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(DownstreamErrorGlobalFilter.class);

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return chain.filter(exchange).onErrorResume(e -> {
            HttpStatus status = statusFor(e);
            if (status == null || exchange.getResponse().isCommitted()) {
                return Mono.error(e);
            }
            log.warn("Servizio a valle non disponibile, rotta={} esito={}: {}", routeId(exchange), status.value(), e.toString());
            return ProblemResponses.write(exchange.getResponse(), status, status == HttpStatus.SERVICE_UNAVAILABLE
                    ? "Servizio temporaneamente non disponibile"
                    : "Risposta non valida dal servizio a valle");
        });
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }

    static HttpStatus statusFor(Throwable error) {
        for (Throwable t = error; t != null; t = t.getCause()) {
            if (t instanceof ConnectException || t instanceof UnknownHostException
                    || t instanceof UnresolvedAddressException) {
                return HttpStatus.SERVICE_UNAVAILABLE;
            }
        }
        for (Throwable t = error; t != null; t = t.getCause()) {
            if (t instanceof IOException) {
                return HttpStatus.BAD_GATEWAY;
            }
        }
        return null;
    }

    private static String routeId(ServerWebExchange exchange) {
        Route route = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
        return route != null ? route.getId() : "?";
    }
}
