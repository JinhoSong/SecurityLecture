package io.security.coresecurity.lecture.security.Filter;

import antlr.StringUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.security.coresecurity.lecture.domain.AccountDto;
import io.security.coresecurity.lecture.security.token.AjaxAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {

    private ObjectMapper objectMapper = new ObjectMapper();

    public AjaxLoginProcessingFilter() {
        // api 위치
        super(new AntPathRequestMatcher("/api/login"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse httpServletResponse) throws AuthenticationException, IOException, ServletException {

        if(!isAjax(request)){
            throw new IllegalStateException("Authentication is not supported");
        }

        AccountDto accountDto = objectMapper.readValue(request.getReader(), AccountDto.class);

        if(accountDto.getUsername() == null || accountDto.getPassword()==null){
            // 둘중 하나라도 null이면
            throw new IllegalArgumentException("Username or Password is empty");
        }
        // 인증처리는 ajax용 토큰을 만들어서 정보를 담고 처리시킨다.

        AjaxAuthenticationToken ajaxAuthenticationToken = new AjaxAuthenticationToken(accountDto.getUsername(),accountDto.getPassword());

        return getAuthenticationManager().authenticate(ajaxAuthenticationToken);
    }
    private boolean isAjax(HttpServletRequest request){

        return "XMLHttpRequest".equals(request.getHeader("X-Requested-With"));


    }
}
