package io.security.coresecurity.lecture.service.impl;

import io.security.coresecurity.lecture.domain.Account;
import io.security.coresecurity.lecture.repository.UserRepository;
import io.security.coresecurity.lecture.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


@Service("userService")
public class UserServiceImpl implements UserService {

    @Autowired
    private UserRepository userRepository;

    @Transactional
    @Override
    public void createUser(Account account) {
        userRepository.save(account);
    }
}
