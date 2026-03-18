package dev.kmandalas.qtspmock.config;

import dev.kmandalas.qtspmock.model.*;
import dev.kmandalas.qtspmock.repository.CredentialRepository;
import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportRuntimeHints;

@Configuration
@ImportRuntimeHints(NativeHintsConfig.ModelHintsRegistrar.class)
public class NativeHintsConfig {

    private static final MemberCategory[] ALL_MEMBER_CATEGORIES = {
            MemberCategory.ACCESS_PUBLIC_FIELDS,
            MemberCategory.ACCESS_DECLARED_FIELDS,
            MemberCategory.INVOKE_PUBLIC_CONSTRUCTORS,
            MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
            MemberCategory.INVOKE_PUBLIC_METHODS,
            MemberCategory.INVOKE_DECLARED_METHODS
    };

    static class ModelHintsRegistrar implements RuntimeHintsRegistrar {

        @Override
        public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
            hints.reflection().registerType(CredentialsListRequest.class, ALL_MEMBER_CATEGORIES);
            hints.reflection().registerType(CredentialsListResponse.class, ALL_MEMBER_CATEGORIES);
            hints.reflection().registerType(CredentialInfoRequest.class, ALL_MEMBER_CATEGORIES);
            hints.reflection().registerType(CredentialInfoResponse.class, ALL_MEMBER_CATEGORIES);
            hints.reflection().registerType(CredentialInfoResponse.KeyInfo.class, ALL_MEMBER_CATEGORIES);
            hints.reflection().registerType(CredentialInfoResponse.CertInfo.class, ALL_MEMBER_CATEGORIES);
            hints.reflection().registerType(CredentialInfoResponse.AuthInfo.class, ALL_MEMBER_CATEGORIES);
            hints.reflection().registerType(CredentialAuthorizeRequest.class, ALL_MEMBER_CATEGORIES);
            hints.reflection().registerType(CredentialAuthorizeResponse.class, ALL_MEMBER_CATEGORIES);
            hints.reflection().registerType(SignHashRequest.class, ALL_MEMBER_CATEGORIES);
            hints.reflection().registerType(SignHashResponse.class, ALL_MEMBER_CATEGORIES);
            hints.reflection().registerType(CredentialRepository.PersistedCredential.class, ALL_MEMBER_CATEGORIES);
        }
    }
}
