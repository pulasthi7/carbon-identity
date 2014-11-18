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

<%@page import="org.apache.axis2.context.ConfigurationContext" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ taglib uri="http://wso2.org/projects/carbon/taglibs/carbontags.jar"
           prefix="carbon" %>
<%@ page import="org.wso2.carbon.CarbonConstants" %>
<%@ page import="org.wso2.carbon.identity.certificateauthority.ui.CaUiConstants" %>
<%@ page import="org.wso2.carbon.identity.certificateauthority.ui.client.CaAdminServiceClient" %>
<%@ page import="org.wso2.carbon.ui.CarbonUIUtil" %>
<%@ page import="org.wso2.carbon.utils.ServerConstants" %>
<%@ page import="org.wso2.carbon.ui.util.CharacterEncoder" %>
<%@ page import="java.util.ResourceBundle" %>
<%@ page import="org.wso2.carbon.ui.CarbonUIMessage" %>


<%
    String forwardTo = "view-csr.jsp?view=true&serialNo=";
    ResourceBundle resourceBundle =
            ResourceBundle.getBundle(CaUiConstants.BUNDLE, request.getLocale());
    try{
        String serverURL = CarbonUIUtil.getServerURL(config.getServletContext(), session);
        ConfigurationContext configContext =
                (ConfigurationContext) config.getServletContext().getAttribute(CarbonConstants.
                        CONFIGURATION_CONTEXT);
        String cookie = (String) session.getAttribute(ServerConstants.ADMIN_SERVICE_COOKIE);
        CaAdminServiceClient client = (CaAdminServiceClient) session.getAttribute(CaUiConstants.CA_ADMIN_CLIENT);

        if (client == null) {
            client = new CaAdminServiceClient(cookie, serverURL, configContext);
            session.setAttribute(CaUiConstants.CA_ADMIN_CLIENT, client);
        }
        String serialNo = "";

        String action = CharacterEncoder.getSafeText(request.getParameter(CaUiConstants.ACTION_PARAM));
        if (CaUiConstants.SIGN_ACTION.equals(action)) {
            serialNo =
                    CharacterEncoder.getSafeText(request.getParameter(CaUiConstants.SERIAL_NO_PARAM));
            int validity = Integer.parseInt(CharacterEncoder.getSafeText(request.getParameter(
                    CaUiConstants.VALIDITY_PARAM)));
            client.sign(serialNo, validity);
        } else if (CaUiConstants.REJECT_ACTION.equals(action)) {
            serialNo =
                    CharacterEncoder.getSafeText(request.getParameter(CaUiConstants.SERIAL_NO_PARAM));
            client.rejectCSR(serialNo);
        }
        forwardTo += serialNo;
    } catch (Exception e) {
        String message = resourceBundle.getString("error.while.signing.csr");
        CarbonUIMessage.sendCarbonUIMessage(message, CarbonUIMessage.ERROR, request);
        forwardTo = "../admin/error.jsp";
        e.printStackTrace();
    }
    //todo: fix url for redirect
    //  response.sendRedirect("/carbon/ca/csr-list-view.jsp");
%>
<script type="text/javascript">

    function forward() {
        location.href = "<%=forwardTo%>";
    }
</script>

<script type="text/javascript">
    forward();
</script>