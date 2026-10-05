package org.secretsharing.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;

@Configuration
public class OpenApiConfiguration {

    @Bean
    public OpenAPI secretSharingOpenApi() {
        return new OpenAPI()
                .info(new Info()
                        .title("Secret Sharing API")
                        .description("""
                                Reactive Shamir secret-sharing service.

                                Share signatures prove that shares were issued by this process instance.
                                They are not a multi-party authenticity scheme: the signing key pair is
                                generated at startup and lost on restart unless you replace that configuration.
                                """)
                        .version("1.0"));
    }
}
