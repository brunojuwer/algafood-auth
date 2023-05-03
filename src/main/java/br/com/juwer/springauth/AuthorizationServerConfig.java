package br.com.juwer.springauth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;

import java.util.Arrays;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
            // Password Credentials
                .withClient("algafood-web")
                .secret(passwordEncoder.encode("web123"))
                .authorizedGrantTypes("password", "refresh_token")
                .scopes("write", "read")
                .accessTokenValiditySeconds(60 * 60 * 6) // seis horas (padrão é 12)
                .refreshTokenValiditySeconds(43200 * 2) // 24 horas

            //Authorization Code Grant Type PKCE
            .and()
                .withClient("food-analytics")
                .secret(passwordEncoder.encode(""))
                .authorizedGrantTypes("authorization_code")
                .scopes("write", "read")
                .redirectUris("http://localhost:4200")

            // Client Credentials
            .and()
                .withClient("backend2")
                .secret(passwordEncoder.encode("123"))
                .authorizedGrantTypes("client_credentials")
                .scopes("write", "read")

            // Implicit Grant
            .and()
                .withClient("webadmin")
                .authorizedGrantTypes("implicit")
                .scopes("write", "read")
                .redirectUris("http://localhost:4200")

            .and()
                .withClient("check_token")
                .secret(passwordEncoder.encode("check123"));
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
            .authenticationManager(authenticationManager)
            .userDetailsService(userDetailsService)
            .reuseRefreshTokens(false)
            .tokenGranter(tokenGranter(endpoints));
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.checkTokenAccess("permitAll()") // não precisa passar senha para verificar token
                .allowFormAuthenticationForClients();
    }

    private TokenGranter tokenGranter(AuthorizationServerEndpointsConfigurer endpoints) {
        var pkceAuthorizationCodeTokenGranter = new PkceAuthorizationCodeTokenGranter(endpoints.getTokenServices(),
                endpoints.getAuthorizationCodeServices(), endpoints.getClientDetailsService(),
                endpoints.getOAuth2RequestFactory());

        var granters = Arrays.asList(
                pkceAuthorizationCodeTokenGranter, endpoints.getTokenGranter());

        return new CompositeTokenGranter(granters);
    }
}
