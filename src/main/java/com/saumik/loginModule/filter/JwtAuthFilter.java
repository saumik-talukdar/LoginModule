package com.saumik.loginModule.filter;

import com.saumik.loginModule.security.AuthUtil;
import com.saumik.loginModule.security.CustomUserDetailsService;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Component
@Slf4j
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final AuthUtil authUtil;
    private final CustomUserDetailsService customUserDetailsService;
    private final HandlerExceptionResolver handlerExceptionResolver;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(7).trim();

        log.info("path :{}", request.getServletPath());
        log.info("JWT Token: {}", token);
        log.info("JWT Token: {}" , token); // ok


        try {
            if (authUtil.isRefreshToken(token)) {
                throw new JwtException("Refresh token cannot access protected endpoints");
            }

            String username = authUtil.getUsernameFromToken(token);
            log.info("JWT Username: {}", username);// ok
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

                if (!authUtil.validateToken(token)) {
                    throw new JwtException("Invalid or expired JWT token");
                }

                // List<? extends GrantedAuthority> authorities = authUtil.extractRoles(token);
                // List<GrantedAuthority> authorities = new ArrayList<>(authUtil.extractRoles(token));

                // Load full UserDetails to set as principal
                UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);

                List<? extends GrantedAuthority> authorities = (List<? extends GrantedAuthority>) userDetails.getAuthorities();

                log.info("Extracted Authorities for context: {}", authorities);
                UsernamePasswordAuthenticationToken auth =
                        new UsernamePasswordAuthenticationToken(userDetails, null, authorities);

                SecurityContextHolder.getContext().setAuthentication(auth);
            }
            log.info("Authentication Success: {}", SecurityContextHolder.getContext().getAuthentication());
            filterChain.doFilter(request, response);

        } catch (JwtException ex) {
            log.warn("JWT validation failed: {}", ex.getMessage());
            handlerExceptionResolver.resolveException(request, response, null, ex);
        } catch (Exception ex) {
            log.error("Unexpected error in JWT filter: {}", ex.getMessage());
            handlerExceptionResolver.resolveException(request, response, null, ex);
        }
    }
}
