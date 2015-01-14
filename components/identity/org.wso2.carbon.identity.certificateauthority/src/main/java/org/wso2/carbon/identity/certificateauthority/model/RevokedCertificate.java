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

package org.wso2.carbon.identity.certificateauthority.model;

import java.util.Date;

/**
 * Represents a revoked certificate
 */
public class RevokedCertificate {

    private String serialNo;
    private Date revokedDate;
    private int reason;

    public RevokedCertificate(String serialNo, Date revokedDate, int reason) {
        this.serialNo = serialNo;
        this.revokedDate = (Date) revokedDate.clone();
        this.reason = reason;
    }

    public String getSerialNo() {
        return serialNo;
    }

    public Date getRevokedDate() {
        return (Date) revokedDate.clone();
    }

    public int getReason() {
        return reason;
    }
}
