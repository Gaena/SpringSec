package com.gaena.securitytest.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecuredController {

    @GetMapping
    public String getGreeting(@RequestBody String greeting) {
        return "Hello world";
    }
}
