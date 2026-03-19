package dev.kmandalas.issuer.util;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;

/**
 * PostgreSQL JDBC driver cannot infer the SQL type for java.time.Instant.
 * Convert to OffsetDateTime (maps to TIMESTAMPTZ) before binding as a parameter.
 */
public final class JdbcUtil {

    private JdbcUtil() {}

    public static OffsetDateTime toOffsetDateTime(Instant instant) {
        return instant == null ? null : instant.atOffset(ZoneOffset.UTC);
    }
}
