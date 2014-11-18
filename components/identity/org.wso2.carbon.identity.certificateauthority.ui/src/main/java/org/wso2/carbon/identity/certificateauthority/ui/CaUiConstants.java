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

package org.wso2.carbon.identity.certificateauthority.ui;

import org.wso2.carbon.identity.certificateauthority.common.RevokeReason;

public class CaUiConstants {

    public static final String BUNDLE = "org.wso2.carbon.identity.certificateauthority.ui.i18n" +
            ".Resources";
    public static final String CA_ADMIN_CLIENT = "CaAdminServiceClient";
    public static final int DEFAULT_ITEMS_PER_PAGE = 10;
    public static final RevokeReason DEFAULT_REVOKE_REASON = RevokeReason
            .REVOCATION_REASON_KEYCOMPROMISE;

    public static final String ACTION_PARAM = "action";
    public static final String STATUS_PARAM = "status";
    public static final String IS_PAGINATED_PARAM = "isPaginated";
    public static final String SEARCH_STRING_PARAM = "searchString";
    public static final String PAGE_NUMBER_PARAM = "pageNumber";
    public static final String SERIAL_NO_PARAM = "serialNo";
    public static final String VALIDITY_PARAM = "validity";
    public static final String SELECTED_REASON_PARAM = "selectedReason";
    public static final String FROM_PARAM = "from";
    public static final String CERTIFICATES_PARAM = "certificates";

    public static final String FROM_PARAM_VALUE_CSR = "csr";
    public static final String FROM_PARAM_VALUE_LIST = "list";

    public static final String CSRS_ATTRIB = "csrs";
    public static final String CERTIFICATES_ATTRIB = "certificates";

    public static final String KEY_CHANGE_ACTION = "keyChange";
    public static final String SIGN_ACTION = "sign";
    public static final String REJECT_ACTION = "reject";
    public static final String REVOKE_MULTIPLE_ACTION = "revoke-multiple";
    public static final String REVOKE_SINGLE_ACTION = "revoke-single";

    public static final String STATUS_ALL = "ALL";
    public static final String SEARCH_STRING_ANY = "*";
}
