package com.bsw.interview.DevsOps.controller;

import com.bsw.interview.DevsOps.model.User;
import com.bsw.interview.DevsOps.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @Autowired
    private UserRepository userRepository;

    @GetMapping("/user/{id}")
    public User getUserById(@PathVariable Long id) {
        return userRepository.findById(id).orElse(null);
    }

    @GetMapping("/")
    public String index() {
        return "Greetings from Spring Boot!";
    }
}