package com.banred.ms_middleware_signcrypt.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Configuration
public class RedisConfig {

    @Value("${microservice.parameters.REDIS_PORT}")
    private int REDIS_PORT;
    @Value("${microservice.parameters.REDIS_USERNAME}")
    private String REDIS_USERNAME;
    @Value("${microservice.parameters.REDIS_PASSWORD}")
    private String REDIS_PASSWORD;
    @Value("${microservice.parameters.REDIS_HOSTNAME}")
    private String REDIS_HOSTNAME;            

    @Bean
    public LettuceConnectionFactory redisConnectionFactory() {
        RedisStandaloneConfiguration config = new RedisStandaloneConfiguration();
        config.setHostName(REDIS_HOSTNAME);
        config.setDatabase(0);
        config.setPort(REDIS_PORT);
        config.setUsername(REDIS_USERNAME);
        config.setPassword(REDIS_PASSWORD); 
        return new LettuceConnectionFactory(config);
    }

    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);

        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(new GenericJackson2JsonRedisSerializer());

        return template;
    }
}
