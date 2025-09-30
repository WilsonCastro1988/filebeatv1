package com.banred.mtlsmock.init;

import com.banred.mtlsmock.model.UserRecord;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
public class RedisInit {

    @Bean
    public CommandLineRunner init(RedisTemplate<String, UserRecord> redisTemplate) {
        return args -> {
            // mTLS clients
            redisTemplate.opsForValue().set("client1", new UserRecord("client1", null, new String[]{"USER"}));
            redisTemplate.opsForValue().set("client2", new UserRecord("client2", null, new String[]{"USER","ADMIN"}));
            redisTemplate.opsForValue().set("cliente-expired", new UserRecord("client-expired", null, new String[]{"USER","ADMIN"}));
            redisTemplate.opsForValue().set("cliente-valid", new UserRecord("client-valid", null, new String[]{"USER","ADMIN"}));


            // Basic Auth users
            BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
            redisTemplate.opsForValue().set("user", new UserRecord("user", encoder.encode("password"), new String[]{"USER"}));
            redisTemplate.opsForValue().set("admin", new UserRecord("admin", encoder.encode("adminpass"), new String[]{"ADMIN"}));
        };
    }
}
