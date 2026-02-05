package com.example.securty.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import com.example.securty.models.User;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
}
