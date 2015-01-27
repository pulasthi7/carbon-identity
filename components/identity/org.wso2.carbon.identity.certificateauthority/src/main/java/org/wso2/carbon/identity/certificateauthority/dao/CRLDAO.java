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
import org.bouncycastle.util.encoders.Base64;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.certificateauthority.CAConstants;
import org.wso2.carbon.identity.certificateauthority.CAException;
import org.wso2.carbon.identity.certificateauthority.CAServerException;
import org.wso2.carbon.identity.certificateauthority.bean.CRLData;
import org.wso2.carbon.identity.certificateauthority.internal.CAServiceComponent;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.user.api.UserStoreException;

import java.io.UnsupportedEncodingException;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Date;

/**
 * Performs DAO operations related to CRLs
 */
public class CRLDAO {
    private static final Log log = LogFactory.getLog(CRLDAO.class);

    /**
     * Add CRL bean into database
     *
     * @param crl               x509 CRL
     * @param tenantDomain      Domain of the tenant who issue the CRL
     * @param thisUpdate        Time of this update
     * @param nextUpdate        Time when next CRL will be released
     * @param crlNumber         The incrementing number for a tenant CA
     * @param deltaCrlIndicator Whether the CRL is a deltaCRL
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public void addCRL(X509CRL crl, String tenantDomain, Date thisUpdate, Date nextUpdate, int crlNumber,
                       int deltaCrlIndicator) throws CAException {
        Connection connection = null;
        String sql = SQLConstants.ADD_CRL_QUERY;
        PreparedStatement prepStmt = null;
        try {
            int tenantId = CAServiceComponent.getRealmService().getTenantManager().getTenantId(tenantDomain);
            connection = IdentityDatabaseUtil.getDBConnection();
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, new String(Base64.encode((crl).getEncoded()),
                    CAConstants.UTF_8_CHARSET));
            prepStmt.setTimestamp(2, new Timestamp(thisUpdate.getTime()));
            prepStmt.setTimestamp(3, new Timestamp(nextUpdate.getTime()));
            prepStmt.setInt(4, crlNumber);
            prepStmt.setInt(5, deltaCrlIndicator);
            prepStmt.setInt(6, tenantId);
            prepStmt.execute();
            connection.commit();
        } catch (UserStoreException e) {
            throw new CAException("Invalid tenant domain :" + tenantDomain, e);
        } catch (IdentityException e) {
            throw new CAServerException("Error when getting an Identity Persistence Store instance.", e);
        } catch (SQLException e) {
            throw new CAServerException("Error when executing the SQL : " + sql, e);
        } catch (CRLException e) {
            throw new CAException("Error when CRL encoding", e);
        } catch (UnsupportedEncodingException e) {
            throw new CAServerException("Error with charset used", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }

    /**
     * Get the latest CRL constructed for a tenant
     *
     * @param tenantDomain Domain of the tenant
     * @param isDeltaCrl   <code>true</code>if delta crl is requested, and <code>false</code> if full crl is requested
     * @return The latest CRL or delta CRL
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public CRLData getLatestCRL(String tenantDomain, boolean isDeltaCrl) throws CAException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet;
        String sql = null;
        try {
            int tenantId = CAServiceComponent.getRealmService().getTenantManager().getTenantId(tenantDomain);
            connection = IdentityDatabaseUtil.getDBConnection();
            if (isDeltaCrl) {
                sql = SQLConstants.GET_LATEST_DELTA_CRL;
            } else {
                sql = SQLConstants.GET_LATEST_CRL;
            }
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setInt(1, tenantId);
            prepStmt.setInt(2, tenantId);
            resultSet = prepStmt.executeQuery();
            if (resultSet.next()) {
                CRLData crlData = null;
                String base64crl = resultSet.getString(SQLConstants.CRL_CONTENT_COLUMN);
                Date thisUpdate = resultSet.getTimestamp(SQLConstants.THIS_UPDATE_COLUMN);
                Date nextUpdate = resultSet.getTimestamp(SQLConstants.NEXT__UPDATE_COLUMN);
                int crlNumber = resultSet.getInt(SQLConstants.CRL_NUMBER_COLUMN);
                int deltaCrlIndicator = resultSet.getInt(SQLConstants.DELTA_CRL_INDICATOR_COLUMN);
                crlData =
                        new CRLData(thisUpdate, nextUpdate, base64crl, tenantId, crlNumber,
                                deltaCrlIndicator);
                return crlData;
            }
        } catch (UserStoreException e) {
            throw new CAException("Invalid tenant domain :" + tenantDomain, e);
        } catch (IdentityException e) {
            throw new CAServerException("Error when getting an Identity Persistence Store instance.", e);
        } catch (SQLException e) {
            throw new CAServerException("Error when executing the SQL : " + sql, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
        throw new CAException("No CRL Data available");
    }

    /**
     * Finds the highest CRL number for given tenant
     *
     * @param tenantDomain Domain of the tenantd of the tenant
     * @param isDeltaCrl   <code>true</code>if delta crl is requested,
     *                     and <code>false</code> if full crl is requested
     * @return Highest CRL number for the tenant
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public int getHighestCrlNumber(String tenantDomain, boolean isDeltaCrl) throws CAException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet;
        String sql = null;

        try {
            int tenantId = CAServiceComponent.getRealmService().getTenantManager().getTenantId(tenantDomain);
            connection = IdentityDatabaseUtil.getDBConnection();
            if (isDeltaCrl) {
                sql = SQLConstants.GET_HIGHEST_DELTA_CRL_NUMBER;
            } else {
                sql = SQLConstants.GET_HIGHEST_CRL_NUMBER;
            }
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setInt(1, tenantId);
            resultSet = prepStmt.executeQuery();
            if (resultSet.next()) {
                return resultSet.getInt(SQLConstants.CRL_COLUMN);
            }
        } catch (UserStoreException e) {
            throw new CAException("Invalid tenant domain :" + tenantDomain, e);
        } catch (IdentityException e) {
            throw new CAServerException("Error when getting an Identity Persistence Store instance.", e);
        } catch (SQLException e) {
            throw new CAServerException("Error when executing the SQL : " + sql, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
        return 0;
    }
}
