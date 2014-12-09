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
import org.bouncycastle.util.encoders.Base64;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.certificateauthority.CaConstants;
import org.wso2.carbon.identity.certificateauthority.CaException;
import org.wso2.carbon.identity.certificateauthority.data.CrlData;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;

import java.io.UnsupportedEncodingException;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.sql.*;
import java.util.Date;

/**
 * Performs DAO operations related to CRLs
 */
public class CrlDAO {
    private static final Log log = LogFactory.getLog(CrlDAO.class);

    /**
     * Add CRL data into database
     *
     * @param crl               x509 CRL
     * @param tenantId          Issuer of the crl
     * @param thisUpdate        Time of this update
     * @param nextUpdate        Time when next CRL will be released
     * @param crlNumber         The incrementing number for a tenant CA
     * @param deltaCrlIndicator Whether the CRL is a deltaCRL
     * @throws CaException
     */
    public void addCRL(X509CRL crl, int tenantId, Date thisUpdate, Date nextUpdate, int crlNumber,
                       int deltaCrlIndicator) throws CaException {
        Connection connection = null;
        String sql = SqlConstants.ADD_CRL_QUERY;
        PreparedStatement prepStmt = null;
        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, new String(Base64.encode((crl).getEncoded()),
                    CaConstants.UTF_8_CHARSET));
            prepStmt.setTimestamp(2, new Timestamp(thisUpdate.getTime()));
            prepStmt.setTimestamp(3, new Timestamp(nextUpdate.getTime()));
            prepStmt.setInt(4, crlNumber);
            prepStmt.setInt(5, deltaCrlIndicator);
            prepStmt.setInt(6, tenantId);
            prepStmt.execute();
            connection.commit();
        } catch (IdentityException e) {
            String errorMsg = "Error when getting an Identity Persistence Store instance.";
            log.error(errorMsg, e);
            throw new CaException(errorMsg, e);
        } catch (SQLException e) {
            log.error("Error when executing the SQL : " + sql,e);
            throw new CaException("Error adding CRL", e);
        } catch (CRLException e) {
            log.error("Error when CRL encoding", e);
            throw new CaException("Error adding CRL", e);
        } catch (UnsupportedEncodingException e) {
            log.error("Error with charset used", e);
            throw new CaException("Error adding CRL", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }

    /**
     * Get the latest CRL constructed for a tenant
     *
     * @param tenantId   Id of the tenant
     * @param isDeltaCrl <code>true</code>if delta crl is requested,
     *                   and <code>false</code> if full crl is requested
     * @return The latest CRL or delta CRL
     * @throws CaException
     */
    public CrlData getLatestCRL(int tenantId, boolean isDeltaCrl) throws CaException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet;
        String sql = null;
        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            if (isDeltaCrl) {
                sql = SqlConstants.GET_LATEST_DELTA_CRL;
            } else {
                sql = SqlConstants.GET_LATEST_CRL;
            }
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setInt(1, tenantId);
            prepStmt.setInt(2, tenantId);
            resultSet = prepStmt.executeQuery();
            if (resultSet.next()) {
                CrlData crlData = null;
                String base64crl = resultSet.getString(SqlConstants.CRL_CONTENT_COLUMN);
                Date thisUpdate = resultSet.getTimestamp(SqlConstants.THIS_UPDATE_COLUMN);
                Date nextUpdate = resultSet.getTimestamp(SqlConstants.NEXT__UPDATE_COLUMN);
                int tenantID = resultSet.getInt(SqlConstants.TENANT_ID_COLUMN);
                int crlNumber = resultSet.getInt(SqlConstants.CRL_NUMBER_COLUMN);
                int deltaCrlIndicator = resultSet.getInt(SqlConstants.DELTA_CRL_INDICATOR_COLUMN);
                crlData =
                        new CrlData(thisUpdate, nextUpdate, base64crl, tenantID, crlNumber,
                                deltaCrlIndicator);
                return crlData;
            }
        } catch (IdentityException e) {
            String errorMsg = "Error when getting an Identity Persistence Store instance.";
            log.error(errorMsg, e);
            throw new CaException(errorMsg, e);
        } catch (SQLException e) {
            log.error("Error when executing the SQL : " + sql,e);
            throw new CaException("Error when retrieving CRL", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
        throw new CaException("No CRL Data available");
    }

    /**
     * Finds the highest CRL number for given tenant
     *
     * @param tenantId   Id of the tenantd of the tenant
     * @param isDeltaCrl <code>true</code>if delta crl is requested,
     *                   and <code>false</code> if full crl is requested
     * @return Highest CRL number for the tenant
     * @throws CaException
     */
    public int getHighestCrlNumber(int tenantId, boolean isDeltaCrl) throws CaException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet;
        String sql = null;

        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            if (isDeltaCrl) {
                sql = SqlConstants.GET_HIGHEST_DELTA_CRL_NUMBER;
            } else {
                sql = SqlConstants.GET_HIGHEST_CRL_NUMBER;
            }
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setInt(1, tenantId);
            resultSet = prepStmt.executeQuery();
            if (resultSet.next()) {
                return resultSet.getInt(SqlConstants.CRL_COLUMN);
            }
        } catch (IdentityException e) {
            String errorMsg = "Error when getting an Identity Persistence Store instance.";
            log.error(errorMsg, e);
            throw new CaException(errorMsg, e);
        } catch (SQLException e) {
            log.error("Error when executing the SQL : " + sql,e);
            throw new CaException("Error when retrieving highest CRL number");
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
        return 0;
    }
}
