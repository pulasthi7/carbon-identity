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

package org.wso2.carbon.identity.certificateauthority.common;

public enum RevokeReason {

    REVOCATION_REASON_UNSPECIFIED (0,"Unspecified"),
    REVOCATION_REASON_KEYCOMPROMISE (1,"Key Compromise"),
    REVOCATION_REASON_CACOMPROMISE (2,"CA Compromise"),
    REVOCATION_REASON_AFFILIATIONCHANGED (3, "Affiliation Changed"),
    REVOCATION_REASON_SUPERSEDED (4,"Superseded"),
    REVOCATION_REASON_CESSATIONOFOPERATION (5,"Cessation of Opearation"),
    REVOCATION_REASON_CERTIFICATEHOLD (6,"Certificate Hold"),
    // Value 7 is not used, see RFC5280
    REVOCATION_REASON_REMOVEFROMCRL (8,"Remove From CRL"),
    REVOCATION_REASON_PRIVILEGESWITHDRAWN (9,"Privileges Withdrawn"),
    REVOCATION_REASON_AACOMPROMISE (10,"AACompromise");

    private final int code;
    private final String displayName;

    RevokeReason(int code, String displayName) {
        this.code = code;
        this.displayName = displayName;
    }

    public int getCode() {
        return code;
    }

    public String getDisplayName() {
        return displayName;
    }

    public static RevokeReason getRevocationReason(int code) throws InvalidArgumentException {
        for (RevokeReason revokeReason : values()) {
            if(revokeReason.code == code){
                return revokeReason;
            }
        }
        throw new InvalidArgumentException("Invalid code ("+code+")");
    }

    public static RevokeReason getRevocationReason(String displayName) throws InvalidArgumentException {
        for (RevokeReason revokeReason : values()) {
            if(revokeReason.displayName.equals(displayName)){
                return revokeReason;
            }
        }
        throw new InvalidArgumentException("Invalid name ("+displayName+")");
    }
}
