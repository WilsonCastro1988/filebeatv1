package com.banred.mtlsmock.service;

import com.banred.mtlsmock.model.UserRecord;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class RedisUserDetailsService implements UserDetailsService {

    @Autowired
    private RedisTemplate<String, UserRecord> redisTemplate;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserRecord record = redisTemplate.opsForValue().get(username);
        if (record == null) throw new UsernameNotFoundException("Usuario/CN no encontrado: " + username);

        return User.withUsername(record.getUsername())
                .password(record.getPassword() != null ? record.getPassword() : "")
                .roles(record.getRoles())
                .build();
    }
}
