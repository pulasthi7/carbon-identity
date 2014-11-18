<%--
  ~ Copyright (c) 2005-2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
  ~
  ~ WSO2 Inc. licenses this file to you under the Apache License,
  ~ Version 2.0 (the "License"); you may not use this file except
  ~ in compliance with the License.
  ~ You may obtain a copy of the License at
  ~
  ~    http://www.apache.org/licenses/LICENSE-2.0
  ~
  ~ Unless required by applicable law or agreed to in writing,
  ~ software distributed under the License is distributed on an
  ~ "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  ~ KIND, either express or implied.  See the License for the
  ~ specific language governing permissions and limitations
  ~ under the License.
  --%>

<%@ page import="org.apache.axis2.context.ConfigurationContext" %>
<%@ page import="org.wso2.carbon.CarbonConstants" %>
<%@ page import="org.wso2.carbon.identity.certificateauthority.common.RevokeReason" %>
<%@ page import="org.wso2.carbon.identity.certificateauthority.ui.client.CaAdminServiceClient" %>
<%@ page import="org.wso2.carbon.ui.CarbonUIMessage" %>

<%
    String serverURL = CarbonUIUtil.getServerURL(config.getServletContext(), session);
    ConfigurationContext configContext =
            (ConfigurationContext) config.getServletContext().getAttribute(
                    CarbonConstants.CONFIGURATION_CONTEXT);
    String cookie = (String) session.getAttribute(ServerConstants.ADMIN_SERVICE_COOKIE);
    String forwardTo = "certificate-list-view.jsp";

    String selectedReason =
            CharacterEncoder.getSafeText(request.getParameter(CaUiConstants.SELECTED_REASON_PARAM));
    int reasonCode = RevokeReason.valueOf(selectedReason).getCode();
    String action = CharacterEncoder.getSafeText(request.getParameter(CaUiConstants.ACTION_PARAM));

    ResourceBundle resourceBundle = ResourceBundle.getBundle(CaUiConstants.BUNDLE, request.getLocale());

    try {
        CaAdminServiceClient client = new CaAdminServiceClient(cookie,
                serverURL, configContext);
        if (CaUiConstants.REVOKE_MULTIPLE_ACTION.equals(action)){
            String[] selectedSerialNos
                    = request.getParameterValues(CaUiConstants.CERTIFICATES_PARAM);
            for (String serialNo : selectedSerialNos) {
                client.revokeCert(serialNo, reasonCode);
            }
        } else if (CaUiConstants.REVOKE_SINGLE_ACTION.equals(action)){
            String serialNo =
                    CharacterEncoder.getSafeText(request.getParameter(CaUiConstants.SERIAL_NO_PARAM));
            String previousPage =
                    CharacterEncoder.getSafeText(request.getParameter(CaUiConstants.FROM_PARAM));
            forwardTo = "view-certificate.jsp?from=" + previousPage + "&serialNo=" + serialNo;
            client.revokeCert(serialNo,reasonCode);
        }
        String message = resourceBundle.getString("certificates.revoked.successfully");
        CarbonUIMessage.sendCarbonUIMessage(message, CarbonUIMessage.INFO, request);
    } catch (Exception e) {
        String message = resourceBundle.getString("certificates.could.not.be.revoked");
        CarbonUIMessage.sendCarbonUIMessage(message, CarbonUIMessage.ERROR, request);
    }
%>


<%@page import="org.wso2.carbon.ui.CarbonUIUtil" %>
<%@ page import="org.wso2.carbon.utils.ServerConstants" %>
<%@ page import="java.util.ResourceBundle" %>
<%@ page import="org.wso2.carbon.identity.certificateauthority.ui.CaUiConstants" %>
<%@ page import="org.wso2.carbon.ui.util.CharacterEncoder" %>
<script
        type="text/javascript">

    function forward() {
        location.href = "<%=forwardTo%>";
    }
</script>

<script type="text/javascript">
    forward();
</script>
