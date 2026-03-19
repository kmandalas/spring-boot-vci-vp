package dev.kmandalas.verifier.config;

import dev.kmandalas.verifier.client.TrustValidatorClient;
import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportRuntimeHints;

/**
 * GraalVM native image hints for record classes used with RestClient JSON serialization.
 */
@Configuration
@ImportRuntimeHints(NativeHintsConfig.VerifierHintsRegistrar.class)
public class NativeHintsConfig {

    private static final MemberCategory[] ALL_MEMBER_CATEGORIES = {
            MemberCategory.ACCESS_PUBLIC_FIELDS,
            MemberCategory.ACCESS_DECLARED_FIELDS,
            MemberCategory.INVOKE_PUBLIC_CONSTRUCTORS,
            MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
            MemberCategory.INVOKE_PUBLIC_METHODS,
            MemberCategory.INVOKE_DECLARED_METHODS
    };

    static class VerifierHintsRegistrar implements RuntimeHintsRegistrar {

        @Override
        public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
            // Records used by TrustValidatorClient (RestClient serialization/deserialization)
            hints.reflection().registerType(TrustValidatorClient.TrustRequest.class, ALL_MEMBER_CATEGORIES);
            hints.reflection().registerType(TrustValidatorClient.TrustResponse.class, ALL_MEMBER_CATEGORIES);
        }
    }
}
