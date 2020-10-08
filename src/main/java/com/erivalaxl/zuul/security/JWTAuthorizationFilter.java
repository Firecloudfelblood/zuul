package com.erivalaxl.zuul.security;

import io.jsonwebtoken.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

public class JWTAuthorizationFilter extends OncePerRequestFilter {

    private final String HEADER_AUTHOTIZATION = "authorization";
    private final String PREFIX = "Barear";
    private final String KEY = "mySecretKey";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try{
            if(existeJWToken(request, response)){
                Claims claims = validateToken(request);
                if (claims.get("authorities") != null){
                    setupSpringAuthentication(claims);
                }else{
                    SecurityContextHolder.clearContext();
                }
            }else{
                SecurityContextHolder.clearContext();
            }
        }catch (ExpiredJwtException | UnsupportedJwtException | MalformedJwtException e){
            e.printStackTrace();
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return;
        }

    }

    private void setupSpringAuthentication(Claims claims) {
        List<String> authorities = (List<String>) claims.get("authorities");
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(claims.getSubject(),
                null,
                authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList())
                );
        SecurityContextHolder.getContext().setAuthentication(auth);
    }

    private Claims validateToken(HttpServletRequest request) {
        String jwToken = request.getHeader(HEADER_AUTHOTIZATION).replace(PREFIX,"");
        return Jwts.parser().setSigningKey(KEY.getBytes()).parseClaimsJws(jwToken).getBody();
    }

    private boolean existeJWToken(HttpServletRequest request, HttpServletResponse response) {
        String authenticationHeader =  request.getHeader(HEADER_AUTHOTIZATION);
        if(authenticationHeader == null || ! authenticationHeader.startsWith(PREFIX)){
            return false;
        }
        return true;
    }
}
