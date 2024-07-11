package com.tianblogs.security.handler.error;

import org.springframework.security.core.AuthenticationException;

public class LoginFailException extends AuthenticationException {
    public LoginFailException(String message) {
        super(message);
    }
}
