package com.banred.ms_middleware_signcrypt.service.Implementation;

import com.banred.ms_middleware_signcrypt.model.Institution;
import com.banred.ms_middleware_signcrypt.model.Institutions;
import com.banred.ms_middleware_signcrypt.service.IInstitutionRedisService;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

@Service
public class InstitutionRedisServiceImpl  implements IInstitutionRedisService {

    private final RedisTemplate<String, Object> redisTemplate;

    public InstitutionRedisServiceImpl(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void saveInstitutions(Institutions institutions) {
        for(Institution institution : institutions.getInstitutions()){
            redisTemplate.opsForValue().set("institution:" + institution.getId(), institution);
        }
    }

    @Override
    public Institution getInstitution(String id) {
        return (Institution) redisTemplate.opsForValue().get("institution:" + id);
    }
    
}
