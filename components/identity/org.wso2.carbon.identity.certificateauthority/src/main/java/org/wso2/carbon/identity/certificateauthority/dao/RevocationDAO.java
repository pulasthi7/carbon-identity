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
import org.wso2.carbon.identity.certificateauthority.common.RevokeReason;
import org.wso2.carbon.identity.certificateauthority.data.RevokedCertificate;
import org.wso2.carbon.identity.core.persistence.JDBCPersistenceManager;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;

import java.sql.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class RevocationDAO {
    private static final Log log = LogFactory.getLog(RevocationDAO.class);

    /**
     * add revoked certificate to the database
     *
     * @param serialNo serialNo of the revoked certificate
     * @param tenantID
     * @param reason   reason for the revoke
     * @throws CaException
     */

    public void addOrUpdateRevokedCertificate(String serialNo, int tenantID, int reason)
            throws CaException {
        Connection connection = null;
        String sql= null;
        PreparedStatement prepStmt = null;
        java.sql.Date updatedAt = new java.sql.Date(new Date().getTime());
        try {
            if(getRevokeReason(serialNo)>=0){
                log.debug("updating revoked certificate's reason");
                sql = SqlConstants.UPDATE_REVOKE_REASON_QUERY;
                connection = JDBCPersistenceManager.getInstance().getDBConnection();
                prepStmt = connection.prepareStatement(sql);
                prepStmt.setInt(1,reason);
                prepStmt.setDate(2, updatedAt);
                prepStmt.setString(3, serialNo);
                prepStmt.setInt(4, tenantID);
            } else {
                log.debug("adding revoked certificate to database");
                connection = JDBCPersistenceManager.getInstance().getDBConnection();
                sql = SqlConstants.ADD_REVOKED_CERTIFICATE_QUERY;
                prepStmt = connection.prepareStatement(sql);
                prepStmt.setString(1,serialNo);
                prepStmt.setDate(2,updatedAt);
                prepStmt.setInt(3,tenantID);
                prepStmt.setInt(4,reason);
            }
            prepStmt.execute();
            connection.commit();
        } catch (IdentityException e) {
            String errorMsg = "Error when getting an Identity Persistence Store instance.";
            log.error(errorMsg, e);
            throw new CaException(errorMsg, e);
        } catch (SQLException e) {
            log.error("Error when executing the SQL : " + sql,e);
            throw new CaException("Error when revoking the certificate", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }

    public int getRevokeReason(String serialNo) throws CaException {
        Connection connection = null;
        String sql = SqlConstants.GET_CERTIFICATE_REVOKED_REASON_QUERY;
        PreparedStatement prepStmt = null;
        try {
            log.debug("adding revoked certificate to database");
            connection = JDBCPersistenceManager.getInstance().getDBConnection();
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, serialNo);
            ResultSet resultSet = prepStmt.executeQuery();
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
        }
    }

    /**
     * get Revoked certificate from serial number
     *
     * @param serialNo
     * @return RevokedCertificate with given serial number
     * @throws CaException
     */
    public RevokedCertificate getRevokedCertificate(String serialNo) throws CaException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet;
        String sql = SqlConstants.GET_REVOKED_CERTIFICATE_QUERY;

        try {
            connection = JDBCPersistenceManager.getInstance().getDBConnection();
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
            log.error("Error when executing the SQL : " + sql);
            throw new CaException("Error when retrieving revoked certificates", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
        throw new CaException("No revoked certificate with given serial number");
    }

    /**
     * get RevokedCertificateArray from resultset
     *
     * @param resultSet
     * @return
     */
    private List<RevokedCertificate> getRevokedCertificatesList(ResultSet resultSet)
            throws SQLException {
        ArrayList<RevokedCertificate> revokedCertificatesList = new ArrayList<RevokedCertificate>();
        while (resultSet.next()) {
            String serialNo = resultSet.getString(SqlConstants.SERIAL_NO_COLUMN);
            int reason = resultSet.getInt(SqlConstants.REVOCATION_REASON_CODE_COLUMN);
            Date revokedDate = resultSet.getDate(SqlConstants.REVOCATION_DATE_COLUMN);
            RevokedCertificate revCertificate =
                    new RevokedCertificate(serialNo, revokedDate, reason);
            revokedCertificatesList.add(revCertificate);
        }
        return revokedCertificatesList;
    }

    /**
     * get revoked certificate by a tenant
     *
     * @param
     * @return
     * @throws CaException
     */
    public List<RevokedCertificate> listRevokedCertificates(int tenantId) throws CaException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet;
        String sql = SqlConstants.LIST_REVOKED_CERTIFICATES_QUERY;
        try {
            connection = JDBCPersistenceManager.getInstance().getDBConnection();
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setInt(1, tenantId);
            resultSet = prepStmt.executeQuery();
            return getRevokedCertificatesList(resultSet);
        } catch (IdentityException e) {
            String errorMsg = "Error when getting an Identity Persistence Store instance.";
            log.error(errorMsg, e);
            throw new CaException(errorMsg, e);
        } catch (SQLException e) {
            log.error("Error when executing the SQL : " + sql);
            throw new CaException("Error when retrieving revoked certificates", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }

    /**
     * remove all actived certificates from revocation table
     *
     * @throws CaException
     */
    public void removeReactivatedCertificates() throws CaException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        String sql = SqlConstants.REMOVE_REACTIVATED_CERTIFICATES_QUERY;

        try {
            connection = JDBCPersistenceManager.getInstance().getDBConnection();
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setInt(1, RevokeReason.REVOCATION_REASON_REMOVEFROMCRL.getCode());
            prepStmt.executeUpdate();
        } catch (IdentityException e) {
            String errorMsg = "Error when getting an Identity Persistence Store instance.";
            log.error(errorMsg, e);
            throw new CaException(errorMsg, e);
        } catch (SQLException e) {
            log.error("Error when executing the SQL : " + sql);
            throw new CaException("Error when removing reactivated certificates", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }

    /**
     * returns revoked certificates after the given date
     *
     * @param tenantId id of the tenant
     * @param date     date to be compared
     * @return set of revoked certificates which are revoked after the given date
     * @throws CaException
     */
    public List<RevokedCertificate> getRevokedCertificatesAfter(int tenantId,
                                                                Date date) throws CaException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet;
        String sql = SqlConstants.LIST_REVOKED_CERTIFICATES_AFTER_QUERY;
        try {
            log.debug("retriving revoked certs after date:" + date + " for tenant :" + tenantId);
            connection = JDBCPersistenceManager.getInstance().getDBConnection();
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
            log.error("Error when executing the SQL : " + sql);
            throw new CaException("Error when retrieving revoked certificates", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }
}

