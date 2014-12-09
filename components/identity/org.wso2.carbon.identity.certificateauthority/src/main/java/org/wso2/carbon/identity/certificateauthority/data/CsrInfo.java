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

package org.wso2.carbon.identity.certificateauthority.data;

import java.util.Date;

/**
 * Represents a CSR
 */
public class CsrInfo {
    private String serialNo;
    private Date requestedDate;
    private String status;

    private String commonName;
    private String organization;
    private String department;
    private String city;
    private String country;
    private String state;

    private String userName;
    private String userStoreDomain;
    private int tenantID;

    public CsrInfo(String serialNo, Date requestedDate, String status, String commonName,
                   String organization, String department, String city, String country,
                   String state, String userName, String userStoreDomain, int tenantID) {
        this.serialNo = serialNo;
        this.requestedDate = (Date) requestedDate.clone();
        this.status = status;
        this.commonName = commonName;
        this.organization = organization;
        this.department = department;
        this.city = city;
        this.country = country;
        this.state = state;
        this.userName = userName;
        this.userStoreDomain = userStoreDomain;
        this.tenantID = tenantID;
    }

    public String getSerialNo() {
        return serialNo;
    }

    public Date getRequestedDate() {
        return (Date) requestedDate.clone();
    }

    public String getStatus() {
        return status;
    }

    public String getCommonName() {
        return commonName;
    }

    public String getOrganization() {
        return organization;
    }

    public String getDepartment() {
        return department;
    }

    public String getCity() {
        return city;
    }

    public String getCountry() {
        return country;
    }

    public String getState() {
        return state;
    }

    public String getUserName() {
        return userName;
    }

    public String getUserStoreDomain() {
        return userStoreDomain;
    }

    public int getTenantID() {
        return tenantID;
    }
}
