package io.security.coresecurity.lecture.security.provider;

import io.security.coresecurity.lecture.security.common.FormAuthenticationDetailsSource;
import io.security.coresecurity.lecture.security.common.FormWebAuthenticationDetails;
import io.security.coresecurity.lecture.security.service.AccountContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 검증 구현
        String username = authentication.getName();
        String password = (String)authentication.getCredentials();


        AccountContext accountContext = (AccountContext) userDetailsService.loadUserByUsername(username);

        // 패스워드 일치 여부 검증
        if(!passwordEncoder.matches(password,accountContext.getAccount().getPassword())){
            throw new BadCredentialsException("BadCrednetialsException");
        }

        // secret key 값 검증
        FormWebAuthenticationDetails formWebAuthenticationDetails = (FormWebAuthenticationDetails)authentication.getDetails();
        String secretKey = formWebAuthenticationDetails.getSecretKey();
        if(secretKey == null || !"secret".equals(secretKey)){
            throw new InsufficientAuthenticationException("InSufficientAuthenticationException");
        }

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities());

        return authenticationToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        // 현재 전달된 class의 타입과 class가 사용하고자 하는 token과 일치하면 인증처리

        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
