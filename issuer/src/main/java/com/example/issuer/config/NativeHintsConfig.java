package com.example.issuer.config;

import com.example.issuer.model.CredentialRequest;
import com.example.issuer.model.CredentialStatusEntry;
import com.example.issuer.model.StatusList;
import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportRuntimeHints;

/**
 * GraalVM native image hints for record classes used with JdbcClient and Spring MVC.
 */
@Configuration
@ImportRuntimeHints(NativeHintsConfig.IssuerHintsRegistrar.class)
public class NativeHintsConfig {

    private static final MemberCategory[] ALL_MEMBER_CATEGORIES = {
            MemberCategory.ACCESS_PUBLIC_FIELDS,
            MemberCategory.ACCESS_DECLARED_FIELDS,
            MemberCategory.INVOKE_PUBLIC_CONSTRUCTORS,
            MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
            MemberCategory.INVOKE_PUBLIC_METHODS,
            MemberCategory.INVOKE_DECLARED_METHODS
    };

    static class IssuerHintsRegistrar implements RuntimeHintsRegistrar {

        @Override
        public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
            // Records used by Spring MVC (@JsonProperty deserialization)
            hints.reflection().registerType(CredentialRequest.class, ALL_MEMBER_CATEGORIES);
            hints.reflection().registerType(CredentialRequest.Proof.class, ALL_MEMBER_CATEGORIES);

            // Records used by JdbcClient.query()
            hints.reflection().registerType(StatusList.class, ALL_MEMBER_CATEGORIES);
            hints.reflection().registerType(CredentialStatusEntry.class, ALL_MEMBER_CATEGORIES);
        }
    }
}
