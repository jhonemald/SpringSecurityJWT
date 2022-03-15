package org.ada.school.user.repository;


import org.ada.school.user.repository.document.User;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface UserRepository
    extends MongoRepository<User, String>
{
    Optional<User> findByEmail( String email );
}
