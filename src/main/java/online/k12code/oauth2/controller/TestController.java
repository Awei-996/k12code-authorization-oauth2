package online.k12code.oauth2.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Carl
 * @since 1.0.0
 */
@RestController
public class TestController {

    @PreAuthorize("hasAuthority('SCOPE_message.read')")
    @GetMapping("/t1")
    public String t1(){
        System.out.println(1111111111);
        return "你好2";
    }
}
