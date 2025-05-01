package com.example.authserver.config;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class ErrorController  implements org.springframework.boot.web.servlet.error.ErrorController {

    @GetMapping("/error")
    @ResponseBody
    public String handleError(HttpServletRequest request) {
        Object error = request.getAttribute(RequestDispatcher.ERROR_EXCEPTION);
        Object message = request.getAttribute(RequestDispatcher.ERROR_MESSAGE);
        Object status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);

        if (error != null) {
            Exception exception = (Exception) error;
            return "Exception: " + exception.getMessage();
        }
        return "Status: " + status + ", Message: " + message;
    }

}
