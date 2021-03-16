package io.security.coresecurity.lecture.repository;

import io.security.coresecurity.lecture.domain.Account;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<Account, Long> {

}
