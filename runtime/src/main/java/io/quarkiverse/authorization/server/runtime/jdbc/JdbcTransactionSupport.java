package io.quarkiverse.authorization.server.runtime.jdbc;

import java.sql.SQLException;

import javax.sql.DataSource;

import io.agroal.api.AgroalDataSource;

/** Internal JDBC support for detecting transaction ownership without starting a transaction. */
public final class JdbcTransactionSupport {

    private static final boolean AGROAL_AVAILABLE = JdbcTransactionSupport.isAgroalAvailable();

    private JdbcTransactionSupport() {
    }

    /**
     * Must be called after acquiring a connection: Agroal associates it with the current transaction on acquisition.
     * Before acquisition, the associated resource may still be null even when a JTA transaction is active.
     * Checking the datasource's own integration also leaves non-JTA datasources independent of an ambient transaction.
     *
     * @throws SQLException if transaction ownership cannot be determined; callers must not fall back to a local commit
     */
    public static boolean isEnlisted(DataSource dataSource) throws SQLException {
        return AGROAL_AVAILABLE && AgroalSupport.isEnlisted(dataSource);
    }

    private static boolean isAgroalAvailable() {
        try {
            Class.forName("io.agroal.api.AgroalDataSource", false, JdbcTransactionSupport.class.getClassLoader());
            return true;
        } catch (ClassNotFoundException ignored) {
            return false;
        }
    }

    // Keep all references to the optional API behind the presence check, including JDBC unwrap.
    private static final class AgroalSupport {

        private static boolean isEnlisted(DataSource dataSource) throws SQLException {
            AgroalDataSource agroal;
            if (dataSource instanceof AgroalDataSource agroalDataSource) {
                agroal = agroalDataSource;
            } else if (dataSource.isWrapperFor(AgroalDataSource.class)) {
                agroal = dataSource.unwrap(AgroalDataSource.class);
            } else {
                return false;
            }
            return agroal.getConfiguration().connectionPoolConfiguration()
                    .transactionIntegration().getTransactionAware() != null;
        }
    }
}
