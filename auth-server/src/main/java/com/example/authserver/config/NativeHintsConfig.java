package com.example.authserver.config;

import com.example.authserver.controller.AuthorizationConsentController;
import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportRuntimeHints;

/**
 * GraalVM native image hints for classes that need reflection access.
 */
@Configuration
@ImportRuntimeHints(NativeHintsConfig.AuthServerHintsRegistrar.class)
public class NativeHintsConfig {

    private static final MemberCategory[] ALL_MEMBER_CATEGORIES = {
            MemberCategory.PUBLIC_FIELDS,
            MemberCategory.DECLARED_FIELDS,
            MemberCategory.INTROSPECT_PUBLIC_CONSTRUCTORS,
            MemberCategory.INTROSPECT_DECLARED_CONSTRUCTORS,
            MemberCategory.INVOKE_PUBLIC_CONSTRUCTORS,
            MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
            MemberCategory.INTROSPECT_PUBLIC_METHODS,
            MemberCategory.INTROSPECT_DECLARED_METHODS,
            MemberCategory.INVOKE_PUBLIC_METHODS,
            MemberCategory.INVOKE_DECLARED_METHODS
    };

    static class AuthServerHintsRegistrar implements RuntimeHintsRegistrar {

        @Override
        public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
            // Register ScopeWithDescription for Thymeleaf template access
            hints.reflection().registerType(
                    AuthorizationConsentController.ScopeWithDescription.class,
                    ALL_MEMBER_CATEGORIES);
        }
    }
}
