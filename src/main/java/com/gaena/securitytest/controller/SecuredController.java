package com.gaena.securitytest.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecuredController {

    @GetMapping("/private")
    public String getSecured(@RequestBody String greeting) {
        return "Secured private";
    }

    @GetMapping("/public")
    public String getMessage() {
        return "Hello from public API controller";
    }
}
