package dukiland.test.msalspring.controller;

import dukiland.test.msalspring.auth.AuthException;
import dukiland.test.msalspring.auth.AuthHelper;
import dukiland.test.msalspring.auth.IdentityContextData;
import dukiland.test.msalspring.auth.servlet.IdentityContextAdapterServlet;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;

@Controller
public class IndexController {

    @GetMapping("/")
    public String index(HttpServletRequest request) {
        if (Objects.isNull(request.getSession().getAttribute("id"))) {
            return "index";
        } else {
            return "succ";
        }
    }

    @GetMapping("/id")
    @ResponseBody
    public String id(HttpServletRequest request) {
        return String.valueOf(request.getSession().getAttribute("id"));
    }

    @GetMapping("/auth/sign_in")
    public void authSignIn(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            if (AuthHelper.singIn(new IdentityContextAdapterServlet(request, response))) {
                response.sendRedirect("/succ.html");
            }
        } catch (AuthException ex) {
            System.out.println(ex.getMessage());
            response.sendRedirect("/error.html");
        }
    }

    @GetMapping("/auth/sign_out")
    public void authSignOut(HttpServletRequest request, HttpServletResponse response) throws IOException {
        request.getSession().invalidate();
        try {
            AuthHelper.signOut(new IdentityContextAdapterServlet(request, response));
        } catch (Exception ex){
            System.out.println(ex.getMessage());
            response.sendRedirect("/error.html");
        }
    }

    @GetMapping("/auth/redirect")
    public void authRedirect(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String returnPage = "/succ.html";
        try {
            IdentityContextAdapterServlet identityContextAdapterServlet = new IdentityContextAdapterServlet(request, response);
            AuthHelper.processAADCallback(identityContextAdapterServlet);

            IdentityContextData context = identityContextAdapterServlet.getContext();
            context.getIdTokenClaims().forEach((key, value) -> {
                System.out.println(key + " : " + value);
                if ("preferred_username".equals(key)) {
                    request.getSession().setAttribute("id", value);
                }
                if ("name".equals(key)) {
                    request.getSession().setAttribute("name", value);
                }
            });
        } catch (AuthException ex) {
            returnPage = "/error.html";
        }
        response.sendRedirect(returnPage);
    }

}
