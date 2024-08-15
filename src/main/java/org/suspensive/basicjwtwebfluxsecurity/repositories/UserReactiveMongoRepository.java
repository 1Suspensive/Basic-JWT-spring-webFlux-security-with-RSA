package org.suspensive.basicjwtwebfluxsecurity.repositories;

import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import org.suspensive.basicjwtwebfluxsecurity.models.User;
import reactor.core.publisher.Mono;

public interface UserReactiveMongoRepository extends ReactiveMongoRepository<User, String> {
    Mono<User> findByUsername(String username);
}
