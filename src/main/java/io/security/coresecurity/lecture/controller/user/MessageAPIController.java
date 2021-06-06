package io.security.coresecurity.lecture.controller.user;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MessageAPIController {

    @GetMapping("/api/messages")
    public String apiMessage(){
        return "API Messages OK";
    }
}
