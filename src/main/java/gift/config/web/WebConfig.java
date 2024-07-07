package gift.config.web;

import gift.config.jwt.JwtAuthenticationFilter;
import gift.util.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.boot.web.servlet.FilterRegistrationBean;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    private final JwtTokenUtil jwtTokenUtil;

    @Autowired
    public WebConfig(JwtTokenUtil jwtTokenUtil) {
        this.jwtTokenUtil = jwtTokenUtil;
    }

    @Bean
    public FilterRegistrationBean<JwtAuthenticationFilter> jwtAuthenticationFilter() {
        FilterRegistrationBean<JwtAuthenticationFilter> registrationBean = new FilterRegistrationBean<>();
        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(jwtTokenUtil);

        registrationBean.setFilter(jwtAuthenticationFilter);
        registrationBean.addUrlPatterns("/api/*"); // API 경로 지정
        registrationBean.setName("JwtAuthenticationFilter");
        registrationBean.setOrder(1);

        return registrationBean;
    }
}
