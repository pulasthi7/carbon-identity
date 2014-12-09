/*
 * Copyright (c) 2005-2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

/**
 * Contains the SQL queries for CA operations
 */
public class SqlConstants {

    private SqlConstants() {
    }

    public static final String SERIAL_NO_COLUMN = "SERIAL_NO";
    public static final String STATUS_COLUMN = "STATUS";
    public static final String CERTIFICATE_COLUMN = "CERTIFICATE";
    public static final String CERTIFICATE_EXPIRY_DATE_COLUMN = "EXPIRY_DATE";
    public static final String CERTIFICATE_ISSUED_DATE_COLUMN = "ISSUED_DATE";
    public static final String USERNAME_COLUMN = "USER_NAME";
    public static final String USERSTORE_DOMAIN_COLUMN = "UM_DOMAIN_NAME";
    public static final String TENANT_ID_COLUMN = "TENANT_ID";
    public static final String CSR_CONTENT_COLUMN = "CSR_CONTENT";
    public static final String REQUESTED_DATE_COLUMN = "REQUESTED_DATE";
    public static final String CSR_ORGANIZATION_COLUMN = "ORGANIZATION";
    public static final String CSR_COMMON_NAME_COLUMN = "COMMON_NAME";
    public static final String REVOCATION_DATE_COLUMN = "REVOKED_DATE";
    public static final String REVOCATION_REASON_CODE_COLUMN = "REASON";

    public static final String CRL_CONTENT_COLUMN = "BASE64CRL";
    public static final String THIS_UPDATE_COLUMN = "THIS_UPDATE";
    public static final String NEXT__UPDATE_COLUMN = "NEXT_UPDATE";
    public static final String CRL_NUMBER_COLUMN = "CRL_NUMBER";
    public static final String DELTA_CRL_INDICATOR_COLUMN = "DELTA_CRL_INDICATOR";
    public static final String CRL_COLUMN = "CRL";

    public static final String KEY_STORE_COLUMN = "KEY_STORE";
    public static final String ALIAS_COLUMN = "ALIAS";

    public static final String TOKEN_COLUMN = "TOKEN";
    public static final String CREATED_TIME_COLUMN = "CREATED_TIME";

    //Certificate related queries
    public static final String ADD_CERTIFICATE_QUERY = "INSERT INTO CA_CERTIFICATE_STORE " +
            "(SERIAL_NO,CERTIFICATE,STATUS,ISSUED_DATE,EXPIRY_DATE,TENANT_ID,USER_NAME," +
            "UM_DOMAIN_NAME) VALUES (?,?,?,?,?,?,?,?)";
    public static final String UPDATE_CERTIFICATE_QUERY =
            "UPDATE CA_CERTIFICATE_STORE SET STATUS= " +
                    "? WHERE SERIAL_NO= ?";
    public static final String GET_CERTIFICATE_QUERY = "SELECT CERTIFICATE FROM " +
            "CA_CERTIFICATE_STORE WHERE SERIAL_NO = ?";
    public static final String GET_CERTIFICATE_INFO_FOR_ADMIN_QUERY = "SELECT * FROM " +
            "CA_CERTIFICATE_STORE WHERE SERIAL_NO = ? AND TENANT_ID = ?";
    public static final String LIST_CERTIFICATES_QUERY = "SELECT * FROM CA_CERTIFICATE_STORE " +
            "WHERE TENANT_ID = ?";
    public static final String LIST_CERTIFICATES_BY_STATUS_QUERY = "SELECT * FROM " +
            "CA_CERTIFICATE_STORE WHERE STATUS = ? AND TENANT_ID =?";

    //CSR related SQL queries
    public static final String ADD_CSR_QUERY = "INSERT INTO CA_CSR_STORE (CSR_CONTENT, STATUS, " +
            "USER_NAME, REQUESTED_DATE, SERIAL_NO, TENANT_ID,COMMON_NAME,ORGANIZATION," +
            "UM_DOMAIN_NAME) VALUES (?,?,?,?,?,?,?,?,?) ";
    public static final String GET_CSR_FOR_USER_QUERY =
            "SELECT * FROM CA_CSR_STORE WHERE SERIAL_NO = ?" +
                    " and USER_NAME= ? AND TENANT_ID =? AND UM_DOMAIN_NAME =?";
    public static final String GET_CSR_CONTENT_QUERY = "SELECT CSR_CONTENT FROM CA_CSR_STORE " +
            "WHERE SERIAL_NO = ?";
    public static final String GET_CSR_FOR_ADMIN_QUERY = "SELECT * FROM CA_CSR_STORE WHERE " +
            "SERIAL_NO = ? and TENANT_ID =? ";
    public static final String UPDATE_CSR_STATUS_QUERY = "UPDATE CA_CSR_STORE SET STATUS= ? WHERE" +
            " SERIAL_NO= ? AND TENANT_ID= ?";
    public static final String DELETE_CSR_QUERY = "DELETE FROM CA_CSR_STORE WHERE SERIAL_NO= ? " +
            "AND TENANT_ID = ?";
    public static final String LIST_CSR_FOR_ADMIN_QUERY = "SELECT * FROM CA_CSR_STORE WHERE " +
            "TENANT_ID = ?";
    public static final String LIST_CSR_FOR_NON_ADMIN_QUERY = "SELECT * FROM CA_CSR_STORE WHERE " +
            "USER_NAME = ? and TENANT_ID= ? and UM_DOMAIN_NAME = ?";
    public static final String LIST_CSR_BY_STATUS_QUERY = "SELECT * FROM CA_CSR_STORE WHERE " +
            "TENANT_ID = ? AND STATUS = ?";

    //Certifite revocation
    public static final String ADD_REVOKED_CERTIFICATE_QUERY = "INSERT INTO " +
            "CA_REVOKED_CERTIFICATES (SERIAL_NO, REVOKED_DATE, TENANT_ID, REASON) VALUES (?,?,?," +
            "?) ";

    public static final String GET_CERTIFICATE_REVOKED_REASON_QUERY = "SELECT REASON FROM " +
            "CA_REVOKED_CERTIFICATES WHERE SERIAL_NO = ?";
    public static final String GET_REVOKED_CERTIFICATE_QUERY =
            "SELECT * FROM CA_REVOKED_CERTIFICATES " +
                    "WHERE SERIAL_NO = ?";
    public static final String LIST_REVOKED_CERTIFICATES_QUERY =
            "SELECT * FROM CA_REVOKED_CERTIFICATES" +
                    " WHERE TENANT_ID = ?";
    public static final String REMOVE_REACTIVATED_CERTIFICATES_QUERY = "DELETE FROM " +
            "CA_REVOKED_CERTIFICATES WHERE REASON = ?";
    public static final String LIST_REVOKED_CERTIFICATES_AFTER_QUERY = "SELECT * FROM " +
            "CA_REVOKED_CERTIFICATES WHERE TENANT_ID = ? and REVOKED_DATE > ?";
    public static final String UPDATE_REVOKE_REASON_QUERY = "UPDATE CA_REVOKED_CERTIFICATES SET " +
            "REASON= ? , REVOKED_DATE = ? WHERE SERIAL_NO= ? AND TENANT_ID=?";

    //CRL
    public static final String ADD_CRL_QUERY = "INSERT INTO CA_CRL_STORE (BASE64CRL, THIS_UPDATE," +
            " NEXT_UPDATE, CRL_NUMBER, DELTA_CRL_INDICATOR, TENANT_ID) VALUES (?,?,?,?,?,?) ";
    public static final String GET_LATEST_DELTA_CRL = "SELECT * FROM CA_CRL_STORE WHERE TENANT_ID" +
            " = ?  AND CRL_NUMBER = SELECT MAX(CRL_NUMBER) FROM CA_CRL_STORE WHERE " +
            "DELTA_CRL_INDICATOR > 0 AND TENANT_ID =?";
    public static final String GET_LATEST_CRL = "SELECT * FROM CA_CRL_STORE WHERE TENANT_ID = ?  " +
            "AND CRL_NUMBER = SELECT MAX(CRL_NUMBER) FROM CA_CRL_STORE WHERE DELTA_CRL_INDICATOR " +
            "= -1 AND TENANT_ID =?";
    public static final String GET_HIGHEST_DELTA_CRL_NUMBER = "SELECT MAX(CRL_NUMBER) AS CRL FROM" +
            " CA_CRL_STORE WHERE TENANT_ID = ?  AND DELTA_CRL_INDICATOR >0 ";
    public static final String GET_HIGHEST_CRL_NUMBER = "SELECT MAX(CRL_NUMBER) AS CRL FROM " +
            "CA_CRL_STORE WHERE TENANT_ID = ?  AND DELTA_CRL_INDICATOR =-1 ";

    //Configuration
    public static final String GET_CA_CONFIGURATION_QUERY = "SELECT * FROM CA_CONFIGURATIONS " +
            "WHERE TENANT_ID = ?";
    public static final String UPDATE_CA_CONFIGURATION_QUERY ="UPDATE CA_CONFIGURATIONS SET " +
            "KEY_STORE_NAME= ?, ALIAS = ? WHERE TENANT_ID = ?";
    public static final String ADD_CA_CONFIGURATION_QUERY = "INSERT INTO CA_CONFIGURATIONS " +
            "(TENANT_ID, KEY_STORE_NAME, ALIAS) VALUES (?,?,?)";

    //SCEP
    public static final String ADD_SCEP_TOKEN = "INSERT INTO CA_SCEP_STORE (TOKEN, CREATED_TIME, " +
            "USER_NAME, TENANT_ID, UM_DOMAIN_NAME) VALUES (?,?,?,?,?)";
    public static final String GET_SCEP_TOKEN = "SELECT * FROM CA_SCEP_STORE WHERE TOKEN = ? AND " +
            "TENANT_ID = ?";
    public static final String UPDATE_SCEP_TOKEN = "UPDATE CA_SCEP_STORE SET SERIAL_NO = ?, " +
            "TRANSACTION_ID = ? WHERE TOKEN = ?";
    public static final String GET_ENROLLED_CERTIFICATE_QUERY = "SELECT CA_CERTIFICATE_STORE" +
            ".CERTIFICATE FROM " +"CA_CERTIFICATE_STORE, CA_SCEP_STORE WHERE CA_CERTIFICATE_STORE" +
            ".SERIAL_NO = CA_SCEP_STORE.SERIAL_NO AND CA_SCEP_STORE.TRANSACTION_ID = ? AND " +
            "CA_SCEP_STORE.TENANT_ID = ?";
}
