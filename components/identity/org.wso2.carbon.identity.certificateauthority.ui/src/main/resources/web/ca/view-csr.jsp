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
<%@ page import="org.wso2.carbon.identity.certificateauthority.common.CsrStatus" %>
<%@ page import="org.wso2.carbon.identity.certificateauthority.stub.CsrInfo" %>
<%@ page import="org.wso2.carbon.identity.certificateauthority.ui.CaUiConstants" %>
<%@ page import="org.wso2.carbon.identity.certificateauthority.ui.client.CaAdminServiceClient" %>
<%@ page import="org.wso2.carbon.ui.CarbonUIMessage" %>
<%@ page import="org.wso2.carbon.ui.CarbonUIUtil" %>
<%@ page import="org.wso2.carbon.ui.util.CharacterEncoder" %>
<%@ page import="org.wso2.carbon.utils.ServerConstants" %>
<%@ page import="java.util.ResourceBundle" %>
<%@ page import="java.text.SimpleDateFormat" %>
<%@ page import="java.text.DateFormat" %>

<%
    String serialNo;


    String forwardTo = null;
    CaAdminServiceClient client = null;
    CsrInfo csr = null;
    DateFormat dateFormat = new SimpleDateFormat("MM/dd/yyyy");

    client = (CaAdminServiceClient) session.getAttribute(CaUiConstants.CA_ADMIN_CLIENT);
    serialNo = CharacterEncoder.getSafeText(request.getParameter(CaUiConstants.SERIAL_NO_PARAM));

    String serverURL = CarbonUIUtil.getServerURL(config.getServletContext(), session);
    ConfigurationContext configContext =
            (ConfigurationContext) config.getServletContext().getAttribute(CarbonConstants.
                    CONFIGURATION_CONTEXT);
    String cookie = (String) session.getAttribute(ServerConstants.ADMIN_SERVICE_COOKIE);
    ResourceBundle resourceBundle =
            ResourceBundle.getBundle(CaUiConstants.BUNDLE, request.getLocale());

    try {

        if (client == null) {
            client = new CaAdminServiceClient(cookie,
                    serverURL, configContext);
            session.setAttribute(CaUiConstants.CA_ADMIN_CLIENT, client);
        }

        if (serialNo != null) {
            csr = client.getCSRFromSerialNo(serialNo);
            if (csr != null) {

%>

<fmt:bundle basename="org.wso2.carbon.identity.certificateauthority.ui.i18n.Resources">
<carbon:breadcrumb
        label="view.csr"
        resourceBundle="org.wso2.carbon.identity.certificateauthority.ui.i18n.Resources"
        topPage="true"
        request="<%=request%>"/>

<script type="text/javascript" src="../carbon/admin/js/breadcrumbs.js"></script>
<script type="text/javascript" src="../carbon/admin/js/cookies.js"></script>
<script type="text/javascript" src="resources/js/main.js"></script>

<script src="../yui/build/yahoo-dom-event/yahoo-dom-event.js" type="text/javascript"></script>
<link href="css/ca.css" rel="stylesheet" type="text/css" media="all"/>

<script type="text/javascript">


    function doCancel() {
        location.href = 'csr-list-view.jsp';
    }

    function getSelectedSubjectType() {
        document.requestForm.submit();
    }

    function viewCertificate(serialNo) {
        location.href = "view-certificate.jsp?from=csr&serialNo=" + serialNo;
    }

    function downloadCertificate(serialNo) {
        location.href = "/ca/certificate/download/" + serialNo + ".crt";
    }
    function signCsr() {
        CARBON.showConfirmationDialog("<fmt:message key="sign.csr"/>", function () {
            document.signForm.action = "csr-actions.jsp";
            document.signForm.submit();
        });
    }
    function rejectCsr() {
        CARBON.showConfirmationDialog("<fmt:message key="reject.csr"/>", function () {
            document.reject.action = "csr-actions.jsp";
            document.reject.submit();
        });
    }

</script>

<div id="middle">

    <h2><fmt:message key="csr.dashboard"/></h2>

    <div id="workArea">
        <div class="sectionSub" style="width: 100%">
            <table style="width: 100%" id="csrDashboard" cellspacing="0" cellpadding="0" border="0">
                <tr>
                    <td width="50%">
                        <table style="width: 100%" id="csrDetails" class="styledLeft">
                            <thead>
                            <tr>
                                <th colspan="2"><fmt:message key='csr.details'/></th>

                            </tr>
                            </thead>
                            <tr>
                                <td style="width: 50%"><fmt:message key='user'/></td>
                                <td><%=csr.getUserName()==null?"":csr.getUserName()%>
                                </td>
                            </tr>
                            <tr>
                                <td><fmt:message key='serial.No'/></td>
                                <td><%=csr.getSerialNo()==null?"":csr.getSerialNo()%>
                                </td>
                            </tr>
                            <tr>
                                <td><fmt:message key='status'/></td>
                                <td><%=csr.getStatus()==null?"":csr.getStatus()%>
                                </td>
                            </tr>
                            <tr>
                                <td><fmt:message key='csr.detail.cn'/></td>
                                <td><%=csr.getCommonName()==null?"":csr.getCommonName()%>
                                </td>
                            </tr>
                            <tr>
                                <td><fmt:message key='csr.detail.dept'/></td>
                                <td><%=csr.getDepartment()==null?"":csr.getDepartment()%>
                                </td>
                            </tr>
                            <tr>
                                <td><fmt:message key='csr.detail.org'/></td>
                                <td><%=csr.getOrganization()==null?"":csr.getOrganization()%>
                                </td>
                            </tr>
                            <tr>
                                <td><fmt:message key='csr.detail.city'/></td>
                                <td><%=csr.getCity()==null?"":csr.getCity()%>
                                </td>
                            </tr>
                            <tr>
                                <td><fmt:message key='csr.detail.state'/></td>
                                <td><%=csr.getState()==null?"":csr.getState()%>
                                </td>
                            </tr>
                            <tr>
                                <td><fmt:message key='csr.detail.country'/></td>
                                <td><%=csr.getCountry()==null?"":csr.getCountry()%>
                                </td>
                            </tr>
                            <tr>
                                <td><fmt:message key='requested.date'/></td>
                                <td><%=csr.getRequestedDate()==null?"":dateFormat.format(csr.getRequestedDate())%>
                                </td>
                            </tr>
                        </table>
                    </td>
                    <td width="10px">&nbsp;</td>
                    <td>
                        <table style="width: 100%" id="actions" class="styledLeft">
                            <thead>
                            <tr>
                                <th colspan="2"><fmt:message key='action'/></th>

                            </tr>
                            </thead>
                            <tbody>
                            <tr>
                                <%
                                    if (CsrStatus.PENDING.toString().equals(csr.getStatus())) {
                                %>
                                <td>
                                    <form method="post" action="" name="signForm">
                                        <table style="width: 100%;border: none;" id="sign">
                                            <tr>
                                                <td style="border: transparent">
                                                    <label for="validity"><fmt:message
                                                            key="days.of.validity"/></label>
                                                </td>
                                                <td style="border: transparent">
                                                    <input type="number" name="validity"
                                                           value="3650" id="validity">
                                                </td>
                                                <input type="hidden" name="action" value="sign"/>
                                                <input type="hidden" name="serialNo"
                                                       value="<%=csr.getSerialNo() %>">
                                                <td style="border: transparent">
                                                    <a onclick="signCsr();return false;"
                                                       href="#"
                                                       style="background-image: url(images/sign.gif);"
                                                       class="icon-link">
                                                        <fmt:message key='sign'/></a>
                                                </td>
                                            </tr>

                                        </table>
                                    </form>
                                </td>
                                <td style="width: 20%;">
                                    <form method="post" action="" name="reject">
                                        <input type="hidden" name="action" value="reject">
                                        <input type="hidden" name="serial"
                                               value="<%=csr.getSerialNo() %>">

                                        <a onclick="rejectCsr();return false;"
                                           href="#"
                                           style="background-image: url(images/reject.gif);"
                                           class="icon-link">
                                            <fmt:message key='reject'/></a>
                                    </form>
                                </td>

                                <%
                                } else if (CsrStatus.SIGNED.toString().equals(csr.getStatus())) {
                                %>
                                <td>
                                    <a onclick="viewCertificate('<%=csr.getSerialNo()%>');return false;"
                                       href="#" style="background-image: url(images/view.gif);"
                                       class="icon-link">
                                        <fmt:message key='view.certificate'/></a>
                                </td>
                                <td>
                                    <a onclick="downloadCertificate('<%=csr.getSerialNo()%>');return false;"
                                       href="#" style="background-image: url(images/download.gif);"
                                       class="icon-link">
                                        <fmt:message key='download.certificate'/></a>
                                </td>
                                <%
                                    }
                                %>
                            </tr>
                            </form>
                            </tbody>
                        </table>
                    </td>
                </tr>
            </table>

        </div>

        <div class="buttonRow">
            <a onclick="doCancel()" class="icon-link" style="background-image:none;"><fmt:message
                    key="back.to.csr.list"/></a>

            <div style="clear:both"></div>
        </div>
        </form>
    </div>
</div>
</fmt:bundle>
<%
            }
        }
        if (csr == null) {
            //serial no is null, or csr not found with given serial
            String message = resourceBundle.getString("csr.not.found");
            CarbonUIMessage.sendCarbonUIMessage(message, CarbonUIMessage.ERROR, request);
            forwardTo = "../admin/error.jsp";
        }
    } catch (Exception e) {
        String message = resourceBundle.getString("error.while.viewing.csr");
        CarbonUIMessage.sendCarbonUIMessage(message, CarbonUIMessage.ERROR, request);
        forwardTo = "../admin/error.jsp";
%>
<script type="text/javascript">
    function forward() {
        location.href = "<%=forwardTo%>";
    }
</script>

<script type="text/javascript">
    forward();
</script>
<%
    }
%>