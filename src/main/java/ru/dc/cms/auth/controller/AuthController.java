package ru.dc.cms.auth.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.view.RedirectView;
import ru.dc.cms.auth.model.UserInfo;
import ru.dc.cms.auth.service.AuthService;

@RestController
public class AuthController {

    private final AuthService authService;

    @Autowired
    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @GetMapping(value = "/auth")
    public RedirectView auth( RedirectAttributes attributes) {
        String ssoAuthPage = authService.getAuthPageUrl();

        attributes.addFlashAttribute("flashAttribute", "redirectWithRedirectView");
        attributes.addAttribute("attribute", "redirectWithRedirectView");
        return new RedirectView(ssoAuthPage);
    }

    @GetMapping(value = "/login/oauth2")
    public String getUserInfo(@RequestParam String code) {

        return code;

        /*
        return userInfo != null
                ? new ResponseEntity<>(userInfo, HttpStatus.OK)
                : new ResponseEntity<>(HttpStatus.NOT_FOUND);
         */
    }
}
