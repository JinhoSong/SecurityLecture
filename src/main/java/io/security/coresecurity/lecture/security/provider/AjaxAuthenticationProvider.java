package io.security.coresecurity.lecture.security.provider;

import io.security.coresecurity.lecture.security.common.FormWebAuthenticationDetails;
import io.security.coresecurity.lecture.security.service.AccountContext;
import io.security.coresecurity.lecture.security.token.AjaxAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.beans.Transient;

public class AjaxAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Bean
    public AuthenticationProvider ajaxAuthenticationProvider(){
        return new AjaxAuthenticationProvider();
    }

    @Override
    @Transient
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 검증 구현
        String username = authentication.getName();
        String password = (String)authentication.getCredentials();

        AccountContext accountContext = (AccountContext) userDetailsService.loadUserByUsername(username);

        System.out.println("A"+accountContext);

        // 패스워드 일치 여부 검증
        if(!passwordEncoder.matches(password,accountContext.getAccount().getPassword())){
            throw new BadCredentialsException("BadCrednetialsException");
        }

        return new AjaxAuthenticationToken(accountContext.getAccount(),null,accountContext.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        // 현재 전달된 class의 타입과 class가 사용하고자 하는 token과 일치하면 인증처리

        return authentication.equals(AjaxAuthenticationToken.class);
    }
}
