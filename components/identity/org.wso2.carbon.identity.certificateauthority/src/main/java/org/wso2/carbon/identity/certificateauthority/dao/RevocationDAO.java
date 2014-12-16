/*
 * Copyright (c) 2005-2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
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
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.certificateauthority.CaException;
import org.wso2.carbon.identity.certificateauthority.common.CertificateStatus;
import org.wso2.carbon.identity.certificateauthority.common.RevokeReason;
import org.wso2.carbon.identity.certificateauthority.data.RevokedCertificate;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;

import java.sql.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Performs revocation related DAO operations
 */
public class RevocationDAO {
    private static final Log log = LogFactory.getLog(RevocationDAO.class);

    /**
     * Add a revoked certificate to the database
     *
     * @param serialNo SerialNo of the revoked certificate
     * @param tenantId The tenant Id
     * @param reason   The reason code for revoking
     * @throws CaException
     * @see org.wso2.carbon.identity.certificateauthority.common.RevokeReason
     */
    public void addRevokedCertificate(String serialNo, int tenantId,
                                              int reason) throws CaException {
        Connection connection = null;
        String sql= null;
        PreparedStatement prepStmt = null;
        Date updatedAt = new Date();
        try {
            if(log.isDebugEnabled()){
                log.debug("Adding revoked reason as "+reason+" of certificate "+serialNo);
            }
            connection = IdentityDatabaseUtil.getDBConnection();
            sql = SqlConstants.ADD_REVOKED_CERTIFICATE_QUERY;
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1,serialNo);
            prepStmt.setTimestamp(2, new Timestamp(updatedAt.getTime()));
            prepStmt.setInt(3,tenantId);
            prepStmt.setInt(4,reason);
            prepStmt.execute();
            updateCertificateStatus(connection,serialNo,reason);
            connection.commit();
        }catch (IdentityException e) {
            log.error("Error when executing the SQL : " + sql,e);
            throw new CaException("Error when revoking the certificate", e);
        } catch (SQLException e) {
            try{
                connection.rollback();
            } catch (SQLException e1) {
                log.error("Error when rolling back the revocation of certificate. Serial " +
                                "no:"+serialNo, e1);
            }
            log.error("Error when revoking certificate. Serial No:"+serialNo+", " +
                    "given reason code:"+reason, e);
            throw new CaException("Error revoking certificate", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection,null,prepStmt);
        }
    }

    /**
     * Update the revoke reason of the given certificate
     * @param serialNo The SerialNo of the revoked certificate
     * @param tenantId The tenant Id
     * @param reason The new reason code for the revocation
     * @throws CaException
     * @see org.wso2.carbon.identity.certificateauthority.common.RevokeReason
     */
    public void updateRevokedCertificate(String serialNo, int tenantId,
                                              int reason) throws CaException {
        Connection connection = null;
        String sql= null;
        PreparedStatement prepStmt = null;
        Date updatedAt = new Date();
        try {
            if(log.isDebugEnabled()){
                log.debug("updating revoked reason to "+reason+" of certificate "+serialNo);
            }
            connection = IdentityDatabaseUtil.getDBConnection();
            sql = SqlConstants.UPDATE_REVOKE_REASON_QUERY;
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setInt(1,reason);
            prepStmt.setTimestamp(2, new Timestamp(updatedAt.getTime()));
            prepStmt.setString(3, serialNo);
            prepStmt.setInt(4, tenantId);
            prepStmt.execute();
            updateCertificateStatus(connection,serialNo,reason);
            connection.commit();
        } catch (IdentityException e) {
            log.error("Error when executing the SQL : " + sql,e);
            throw new CaException("Error when updating the revoke reason", e);
        } catch (SQLException e) {
            try{
                connection.rollback();
            } catch (SQLException e1) {
                log.error("Error when rolling back the update of revoke reason",e1);
            }
            log.error("Error updating revoke reason for certificate. Serial No:"+serialNo,e);
            throw new CaException("Error updating revoke reason", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }

    /**
     * Updates the certificate status based on whether the reason is "Remove from CRL"
     * @param connection The db connection which does the db updates related
     * @param serialNo The SerialNo of the revoked certificate
     * @param reason The reason code for revoking
     * @throws SQLException
     */
    private void updateCertificateStatus(Connection connection, String serialNo, int reason)
            throws SQLException {
        CertificateDAO certificateDAO = new CertificateDAO();
        if (reason == RevokeReason.REVOCATION_REASON_REMOVEFROMCRL.getCode()) {
            //Undo previous revoking
            certificateDAO.updateCertificateStatus(connection,serialNo,
                    CertificateStatus.ACTIVE.toString());
        } else {
            certificateDAO.updateCertificateStatus(connection,serialNo,
                    CertificateStatus.REVOKED.toString());
        }
    }

    /**
     * Gets the revoke reason of the certificate
     * @param serialNo
     * @return The reason code for the revocation if the certificate is revoked,
     * -1 if certificate is not revoked, or not available
     * @throws CaException
     */
    public int getRevokeReason(String serialNo) throws CaException {
        Connection connection = null;
        String sql = SqlConstants.GET_CERTIFICATE_REVOKED_REASON_QUERY;
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, serialNo);
            resultSet = prepStmt.executeQuery();
            if (resultSet.next()) {
                return resultSet.getInt(SqlConstants.REVOCATION_REASON_CODE_COLUMN);
            } else {
                return -1;
            }
        } catch (SQLException e) {
            log.error("Error when executing the SQL : " + sql, e);
            throw new CaException("Error when getting revoke reason of the certificate", e);
        } catch (IdentityException e) {
            String errorMsg = "Error when getting an Identity Persistence Store instance.";
            log.error(errorMsg, e);
            throw new CaException(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }
    }

    /**
     * Get Revoked certificate details from serial number
     *
     * @param serialNo The SerialNo of the revoked certificate
     * @return The details of the revoked certificate
     * @throws CaException
     */
    public RevokedCertificate getRevokedCertificate(String serialNo) throws CaException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        String sql = SqlConstants.GET_REVOKED_CERTIFICATE_QUERY;

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
            String errorMsg = "Error when getting an Identity Persistence Store instance.";
            log.error(errorMsg, e);
            throw new CaException(errorMsg, e);
        } catch (SQLException e) {
            log.error("Error when executing the SQL : " + sql,e);
            throw new CaException("Error when retrieving revoked certificates", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }
        throw new CaException("No revoked certificate with given serial number");
    }

    /**
     * Gets RevokedCertificate list from a ResultSet
     * @param resultSet The resultSet where the Revoked Certificate details are
     * @return List of the details of the revoked certificates
     */
    private List<RevokedCertificate> getRevokedCertificatesList(ResultSet resultSet)
            throws SQLException {
        ArrayList<RevokedCertificate> revokedCertificatesList = new ArrayList<RevokedCertificate>();
        while (resultSet.next()) {
            String serialNo = resultSet.getString(SqlConstants.SERIAL_NO_COLUMN);
            int reason = resultSet.getInt(SqlConstants.REVOCATION_REASON_CODE_COLUMN);
            Date revokedDate = resultSet.getTimestamp(SqlConstants.REVOCATION_DATE_COLUMN);
            RevokedCertificate revCertificate =
                    new RevokedCertificate(serialNo, revokedDate, reason);
            revokedCertificatesList.add(revCertificate);
        }
        return revokedCertificatesList;
    }

    /**
     * Gets revoked certificates by a tenant
     *
     * @param tenantId The tenant Id
     * @return List of Revoked certificates by the tenant
     * @throws CaException
     */
    public List<RevokedCertificate> listRevokedCertificates(int tenantId) throws CaException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        String sql = SqlConstants.LIST_REVOKED_CERTIFICATES_QUERY;
        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setInt(1, tenantId);
            resultSet = prepStmt.executeQuery();
            return getRevokedCertificatesList(resultSet);
        } catch (IdentityException e) {
            String errorMsg = "Error when getting an Identity Persistence Store instance.";
            log.error(errorMsg, e);
            throw new CaException(errorMsg, e);
        } catch (SQLException e) {
            log.error("Error when executing the SQL : " + sql,e);
            throw new CaException("Error when retrieving revoked certificates", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }
    }

    /**
     * Remove all activated certificates (after temporary revocation) from revocation table
     * @throws CaException
     */
    public void removeReactivatedCertificates() throws CaException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        String sql = SqlConstants.REMOVE_REACTIVATED_CERTIFICATES_QUERY;

        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setInt(1, RevokeReason.REVOCATION_REASON_REMOVEFROMCRL.getCode());
            prepStmt.executeUpdate();
            connection.commit();
        } catch (IdentityException e) {
            String errorMsg = "Error when getting an Identity Persistence Store instance.";
            log.error(errorMsg, e);
            throw new CaException(errorMsg, e);
        } catch (SQLException e) {
            log.error("Error when executing the SQL : " + sql,e);
            throw new CaException("Error when removing reactivated certificates", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }

    /**
     * Gets revoked certificates after the given timestamp
     *
     * @param tenantId The tenant Id
     * @param date     The timestamp from when the revoked certificates are listed
     * @return The list of revoked certificates which are revoked after the given timestamp
     * @throws CaException
     */
    public List<RevokedCertificate> getRevokedCertificatesAfter(int tenantId,
                                                                Date date) throws CaException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        String sql = SqlConstants.LIST_REVOKED_CERTIFICATES_AFTER_QUERY;
        try {
            if(log.isDebugEnabled()){
                log.debug("retrieving revoked certs after date:" + date + " for tenant :" + tenantId);
            }
            connection = IdentityDatabaseUtil.getDBConnection();
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setInt(1, tenantId);
            prepStmt.setTimestamp(2, new Timestamp(date.getTime()));
            resultSet = prepStmt.executeQuery();
            return getRevokedCertificatesList(resultSet);
        } catch (IdentityException e) {
            String errorMsg = "Error when getting an Identity Persistence Store instance.";
            log.error(errorMsg, e);
            throw new CaException(errorMsg, e);
        } catch (SQLException e) {
            log.error("Error when executing the SQL : " + sql,e);
            throw new CaException("Error when retrieving revoked certificates", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }
    }
}
