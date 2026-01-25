package com.example.walletprovider.config;

import com.example.walletprovider.model.*;
import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportRuntimeHints;

/**
 * GraalVM native image hints for record classes used with JdbcClient.
 */
@Configuration
@ImportRuntimeHints(NativeHintsConfig.ModelHintsRegistrar.class)
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

    static class ModelHintsRegistrar implements RuntimeHintsRegistrar {

        @Override
        public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
            // Register all record classes that need reflection (used by JdbcClient.query())
            hints.reflection().registerType(StatusList.class, ALL_MEMBER_CATEGORIES);
            hints.reflection().registerType(WalletUnitAttestation.class, ALL_MEMBER_CATEGORIES);
            hints.reflection().registerType(KeyAttestationData.class, ALL_MEMBER_CATEGORIES);
            hints.reflection().registerType(WuaCredentialRequest.class, ALL_MEMBER_CATEGORIES);
            hints.reflection().registerType(WuaCredentialRequest.Proof.class, ALL_MEMBER_CATEGORIES);
            hints.reflection().registerType(WuaCredentialRequest.KeyAttestation.class, ALL_MEMBER_CATEGORIES);
            hints.reflection().registerType(WiaCredentialRequest.class, ALL_MEMBER_CATEGORIES);
            hints.reflection().registerType(WiaCredentialRequest.Proof.class, ALL_MEMBER_CATEGORIES);
        }
    }
}
