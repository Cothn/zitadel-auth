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

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

@RestController
public class AuthController {

    private final AuthService authService;

    @Autowired
    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @GetMapping(value = "/auth")
    public RedirectView auth(RedirectAttributes attributes) {
        String ssoAuthPage = authService.getAuthPageUrl();

        attributes.addFlashAttribute("flashAttribute", "redirectWithRedirectView");
        attributes.addAttribute("attribute", "redirectWithRedirectView");
        return new RedirectView(ssoAuthPage);
    }

    @GetMapping(value = "/login/oauth2")
    public String getTokenInfo(RedirectAttributes attributes,
                                     @RequestParam(required = false) String code) throws IOException, InterruptedException, URISyntaxException {
        String tokenRequest = authService.getTokenRequest(code);

        HttpRequest request = HttpRequest.newBuilder(new URI(tokenRequest)).build();

        HttpClient client = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        System.out.println(response.statusCode() );
        System.out.println(response.body() );

        return response.body();
    }

    @GetMapping(value = "/user/me")
    public String getUserInfo(@RequestParam String code) {

        return code;

        /*
        return userInfo != null
                ? new ResponseEntity<>(userInfo, HttpStatus.OK)
                : new ResponseEntity<>(HttpStatus.NOT_FOUND);
         */
    }
}
