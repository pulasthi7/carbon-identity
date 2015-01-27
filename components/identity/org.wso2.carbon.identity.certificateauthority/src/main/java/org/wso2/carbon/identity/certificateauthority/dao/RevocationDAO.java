/*
 * Copyright (c) 2015 WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.certificateauthority.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.x509.CRLReason;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.certificateauthority.CAException;
import org.wso2.carbon.identity.certificateauthority.CAServerException;
import org.wso2.carbon.identity.certificateauthority.bean.RevokedCertificate;
import org.wso2.carbon.identity.certificateauthority.common.CertificateStatus;
import org.wso2.carbon.identity.certificateauthority.internal.CAServiceComponent;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.user.api.UserStoreException;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Performs revocation related DAO operations.
 */
public class RevocationDAO {
    private static final Log log = LogFactory.getLog(RevocationDAO.class);

    /**
     * Add a revoked certificate to the database.
     *
     * @param serialNo     SerialNo of the revoked certificate
     * @param tenantDomain The tenant domain
     * @param reason       The reason code for revoking
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     * @see org.bouncycastle.asn1.x509.CRLReason
     */
    public void addRevokedCertificate(String serialNo, String tenantDomain, int reason) throws CAException {
        Connection connection = null;
        String sql = null;
        PreparedStatement prepStmt = null;
        Date updatedAt = new Date();
        try {
            if (log.isDebugEnabled()) {
                log.debug("Adding revoked reason as " + reason + " of certificate " + serialNo);
            }
            int tenantId = CAServiceComponent.getRealmService().getTenantManager().getTenantId(tenantDomain);
            connection = IdentityDatabaseUtil.getDBConnection();
            sql = SQLConstants.ADD_REVOKED_CERTIFICATE_QUERY;
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, serialNo);
            prepStmt.setTimestamp(2, new Timestamp(updatedAt.getTime()));
            prepStmt.setInt(3, tenantId);
            prepStmt.setInt(4, reason);
            prepStmt.execute();
            updateCertificateStatus(connection, serialNo, reason);
            connection.commit();
        } catch (UserStoreException e) {
            throw new CAException("Invalid tenant domain :" + tenantDomain, e);
        } catch (IdentityException e) {
            throw new CAServerException("Error when executing the SQL : " + sql, e);
        } catch (SQLException e) {
            try {
                connection.rollback();
            } catch (SQLException e1) {
                log.error("Error when rolling back the revocation of certificate. Serial " +
                        "no:" + serialNo, e1);
            }
            throw new CAServerException("Error when revoking certificate. Serial No:" + serialNo + ", " +
                    "given reason code:" + reason, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }

    /**
     * Update the revoke reason of the given certificate.
     *
     * @param serialNo     The SerialNo of the revoked certificate
     * @param tenantDomain The tenant domain
     * @param reason       The new reason code for the revocation
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     * @see org.bouncycastle.asn1.x509.CRLReason
     */
    public void updateRevokedCertificate(String serialNo, String tenantDomain, int reason) throws CAException {
        Connection connection = null;
        String sql = null;
        PreparedStatement prepStmt = null;
        Date updatedAt = new Date();
        try {
            if (log.isDebugEnabled()) {
                log.debug("updating revoked reason to " + reason + " of certificate " + serialNo);
            }
            int tenantId = CAServiceComponent.getRealmService().getTenantManager().getTenantId(tenantDomain);
            connection = IdentityDatabaseUtil.getDBConnection();
            sql = SQLConstants.UPDATE_REVOKE_REASON_QUERY;
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setInt(1, reason);
            prepStmt.setTimestamp(2, new Timestamp(updatedAt.getTime()));
            prepStmt.setString(3, serialNo);
            prepStmt.setInt(4, tenantId);
            prepStmt.execute();
            updateCertificateStatus(connection, serialNo, reason);
            connection.commit();
        } catch (UserStoreException e) {
            throw new CAException("Invalid tenant domain :" + tenantDomain, e);
        } catch (IdentityException e) {
            throw new CAServerException("Error when executing the SQL : " + sql, e);
        } catch (SQLException e) {
            try {
                connection.rollback();
            } catch (SQLException e1) {
                log.error("Error when rolling back the update of revoke reason", e1);
            }
            throw new CAServerException("Error updating revoke reason for certificate. Serial No:" + serialNo, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }

    /**
     * Updates the certificate status based on whether the reason is "Remove from CRL".
     *
     * @param connection The db connection which does the db updates related
     * @param serialNo   The SerialNo of the revoked certificate
     * @param reason     The reason code for revoking
     * @throws SQLException
     */
    private void updateCertificateStatus(Connection connection, String serialNo, int reason) throws SQLException {
        CertificateDAO certificateDAO = new CertificateDAO();
        if (reason == CRLReason.removeFromCRL) {
            //Undo previous revoking
            certificateDAO.updateCertificateStatus(connection, serialNo,
                    CertificateStatus.ACTIVE.toString());
        } else {
            certificateDAO.updateCertificateStatus(connection, serialNo,
                    CertificateStatus.REVOKED.toString());
        }
    }

    /**
     * Gets the revoke reason of the certificate.
     *
     * @param serialNo
     * @return The reason code for the revocation if the certificate is revoked,
     * -1 if certificate is not revoked, or not available
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public int getRevokeReason(String serialNo) throws CAException {
        Connection connection = null;
        String sql = SQLConstants.GET_CERTIFICATE_REVOKED_REASON_QUERY;
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, serialNo);
            resultSet = prepStmt.executeQuery();
            if (resultSet.next()) {
                return resultSet.getInt(SQLConstants.REVOCATION_REASON_CODE_COLUMN);
            } else {
                return -1;
            }
        } catch (SQLException e) {
            throw new CAServerException("Error when executing the SQL : " + sql, e);
        } catch (IdentityException e) {
            throw new CAServerException("Error when getting an Identity Persistence Store instance.", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }
    }

    /**
     * Get Revoked certificate details from serial number.
     *
     * @param serialNo The SerialNo of the revoked certificate
     * @return The details of the revoked certificate
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public RevokedCertificate getRevokedCertificate(String serialNo) throws CAException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        String sql = SQLConstants.GET_REVOKED_CERTIFICATE_QUERY;

        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            prepStmt = connection.prepareStatement(sql);

            prepStmt.setString(1, serialNo);
            resultSet = prepStmt.executeQuery();
            List<RevokedCertificate> revokedCertificatesList =
                    getRevokedCertificatesList(resultSet);
            if (!revokedCertificatesList.isEmpty()) {
                return revokedCertificatesList.get(0);
            }
        } catch (IdentityException e) {
            throw new CAServerException("Error when getting an Identity Persistence Store instance.", e);
        } catch (SQLException e) {
            throw new CAServerException("Error when executing the SQL : " + sql, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }
        return null;
    }

    /**
     * Gets RevokedCertificate list from a ResultSet.
     *
     * @param resultSet The resultSet where the Revoked Certificate details are
     * @return List of the details of the revoked certificates
     */
    private List<RevokedCertificate> getRevokedCertificatesList(ResultSet resultSet)
            throws SQLException {
        ArrayList<RevokedCertificate> revokedCertificatesList = new ArrayList<RevokedCertificate>();
        while (resultSet.next()) {
            String serialNo = resultSet.getString(SQLConstants.SERIAL_NO_COLUMN);
            int reason = resultSet.getInt(SQLConstants.REVOCATION_REASON_CODE_COLUMN);
            Date revokedDate = resultSet.getTimestamp(SQLConstants.REVOCATION_DATE_COLUMN);
            RevokedCertificate revCertificate =
                    new RevokedCertificate(serialNo, revokedDate, reason);
            revokedCertificatesList.add(revCertificate);
        }
        return revokedCertificatesList;
    }

    /**
     * Gets revoked certificates by a tenant.
     *
     * @param tenantDomain The tenant domain
     * @return List of Revoked certificates by the tenant
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public List<RevokedCertificate> listRevokedCertificates(String tenantDomain) throws CAException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        String sql = SQLConstants.LIST_REVOKED_CERTIFICATES_QUERY;
        try {
            int tenantId = CAServiceComponent.getRealmService().getTenantManager().getTenantId(tenantDomain);
            connection = IdentityDatabaseUtil.getDBConnection();
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setInt(1, tenantId);
            resultSet = prepStmt.executeQuery();
            return getRevokedCertificatesList(resultSet);
        } catch (IdentityException e) {
            throw new CAServerException("Error when getting an Identity Persistence Store instance.", e);
        } catch (SQLException e) {
            throw new CAServerException("Error when executing the SQL : " + sql, e);
        } catch (UserStoreException e) {
            throw new CAException("Invalid tenant domain :" + tenantDomain, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }
    }

    /**
     * Remove all activated certificates (after temporary revocation) from revocation table.
     *
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public void removeReactivatedCertificates() throws CAException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        String sql = SQLConstants.REMOVE_REACTIVATED_CERTIFICATES_QUERY;

        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setInt(1, CRLReason.removeFromCRL);
            prepStmt.executeUpdate();
            connection.commit();
        } catch (IdentityException e) {
            throw new CAServerException("Error when getting an Identity Persistence Store instance.", e);
        } catch (SQLException e) {
            throw new CAServerException("Error when executing the SQL : " + sql, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }

    /**
     * Gets revoked certificates after the given timestamp.
     *
     * @param tenantDomain The tenant domain
     * @param date         The timestamp from when the revoked certificates are listed
     * @return The list of revoked certificates which are revoked after the given timestamp
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public List<RevokedCertificate> getRevokedCertificatesAfter(String tenantDomain, Date date) throws CAException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        String sql = SQLConstants.LIST_REVOKED_CERTIFICATES_AFTER_QUERY;
        try {
            int tenantId = CAServiceComponent.getRealmService().getTenantManager().getTenantId(tenantDomain);
            if (log.isDebugEnabled()) {
                log.debug("retrieving revoked certs after date:" + date + " for tenant :" + tenantId);
            }
            connection = IdentityDatabaseUtil.getDBConnection();
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setInt(1, tenantId);
            prepStmt.setTimestamp(2, new Timestamp(date.getTime()));
            resultSet = prepStmt.executeQuery();
            return getRevokedCertificatesList(resultSet);
        } catch (UserStoreException e) {
            throw new CAException("Invalid tenant domain :" + tenantDomain, e);
        } catch (IdentityException e) {
            throw new CAServerException("Error when getting an Identity Persistence Store instance.", e);
        } catch (SQLException e) {
            throw new CAServerException("Error when executing the SQL : " + sql, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }
    }
}

