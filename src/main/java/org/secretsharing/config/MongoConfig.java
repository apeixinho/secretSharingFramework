package org.secretsharing.config;

import com.mongodb.MongoClientSettings;
import com.mongodb.MongoCredential;
import com.mongodb.ServerAddress;
import com.mongodb.reactivestreams.client.MongoClient;
import com.mongodb.reactivestreams.client.MongoClients;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.mongodb.config.AbstractReactiveMongoConfiguration;

import static java.util.Collections.singletonList;

/**
 * Created by jt, Spring Framework Guru.
 */
@Configuration
public class MongoConfig extends AbstractReactiveMongoConfiguration {

    @Value("${secret-sharing.mongo-credentials.mongouser}")
    private String mongoUser;

    @Value("${secret-sharing.mongo-credentials.mongopass}")
    private String mongoPass;

    @Value("${secret-sharing.mongo-credentials.mongodb}")
    private String mongoDB;


    @Bean
    public MongoClient mongoClient() {
        return MongoClients.create();
    }

    @Override
    protected String getDatabaseName() {
        return this.mongoDB;
    }

    @Override
    protected void configureClientSettings(MongoClientSettings.Builder builder) {
        builder.credential(MongoCredential.createCredential(mongoUser,
                mongoDB, mongoPass.toCharArray()))
                .applyToClusterSettings(settings -> {
                    settings.hosts((singletonList(
                            new ServerAddress("127.0.0.1", 27017)
                    )));
                });
    }
}











