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

<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ taglib uri="http://wso2.org/projects/carbon/taglibs/carbontags.jar"
           prefix="carbon" %>
<%@ page import="org.apache.axis2.context.ConfigurationContext" %>
<%@ page import="org.wso2.carbon.CarbonConstants" %>
<%@ page import="org.wso2.carbon.identity.certificateauthority.common.CertificateStatus" %>
<%@ page import="org.wso2.carbon.identity.certificateauthority.common.RevokeReason" %>
<%@ page import="org.wso2.carbon.identity.certificateauthority.stub.CertificateInfo" %>
<%@ page import="org.wso2.carbon.identity.certificateauthority.ui.CaUiConstants" %>
<%@ page import="org.wso2.carbon.identity.certificateauthority.ui.client.CaAdminServiceClient" %>
<%@ page import="org.wso2.carbon.identity.certificateauthority.ui.util.ClientUtil" %>
<%@ page import="org.wso2.carbon.ui.CarbonUIUtil" %>
<%@ page import="org.wso2.carbon.ui.util.CharacterEncoder" %>
<%@ page import="org.wso2.carbon.utils.ServerConstants" %>
<%@ page import="org.wso2.carbon.utils.CarbonUtils" %>
<%

    CertificateInfo[] certificatesToDisplay = null;


    CaAdminServiceClient client = null;
    CertificateInfo[] certificates = null;

    String statusTypeFilter =
            CharacterEncoder.getSafeText(request.getParameter(CaUiConstants.STATUS_PARAM));
    if (statusTypeFilter == null || "".equals(statusTypeFilter)) {
        statusTypeFilter = CaUiConstants.STATUS_ALL;
    }

    int numberOfPages = 0;
    boolean isPaginated =
            Boolean.parseBoolean(request.getParameter(CaUiConstants.IS_PAGINATED_PARAM));
    String certSearchString =
            CharacterEncoder.getSafeText(request.getParameter(CaUiConstants.SEARCH_STRING_PARAM));
    if (certSearchString == null) {
        certSearchString = CaUiConstants.SEARCH_STRING_ANY;
    } else {
        certSearchString = certSearchString.trim();
    }
    String paginationValue = CaUiConstants.IS_PAGINATED_PARAM + "=true&" +
            CaUiConstants.SEARCH_STRING_PARAM + "=" + certSearchString;

    String pageNumber =
            CharacterEncoder.getSafeText(request.getParameter(CaUiConstants.PAGE_NUMBER_PARAM));

    int pageNumberInt = 0;
    if (pageNumber != null) {
        try {
            pageNumberInt = Integer.parseInt(pageNumber);
        } catch (NumberFormatException ignored) {
            // ignored since defaults to 0
        }
    }

    String serverURL = CarbonUIUtil.getServerURL(config.getServletContext(), session);
    ConfigurationContext configContext =
            (ConfigurationContext) config.getServletContext().getAttribute(CarbonConstants.
                    CONFIGURATION_CONTEXT);
    String cookie = (String) session.getAttribute(ServerConstants.ADMIN_SERVICE_COOKIE);
    try {


        if (client == null) {
            client = new CaAdminServiceClient(cookie,
                    serverURL, configContext);
            session.setAttribute(CaUiConstants.CA_ADMIN_CLIENT, client);
        }

        String previousFilter = (String) session.getAttribute(CaUiConstants.CERTIFICATES_FILTER_ATTRIB);
        if(!statusTypeFilter.equals(previousFilter)){
            session.setAttribute(CaUiConstants.CERTIFICATES_FILTER_ATTRIB,statusTypeFilter);
            if (statusTypeFilter.equals(CaUiConstants.STATUS_ALL)) {
                certificates = client.getCertificateList();
            } else {
                certificates = client.getCertificatesFromStatus(statusTypeFilter);
            }
            session.setAttribute(CaUiConstants.CERTIFICATES_ATTRIB, certificates);
        } else {
            certificates = (CertificateInfo[])session.getAttribute(CaUiConstants.CERTIFICATES_ATTRIB);
        }

        int itemsPerPageInt = CaUiConstants.DEFAULT_ITEMS_PER_PAGE;

        if (certificates != null) {
//            numberOfPages = (int) Math.ceil((double) certificates.length / itemsPerPageInt);
            numberOfPages = (certificates.length + itemsPerPageInt - 1) / itemsPerPageInt;
            certificatesToDisplay =
                    ClientUtil.doPagingForCertificates(pageNumberInt, itemsPerPageInt,
                            certificates);
        }
    } catch (Exception e) {
%>

<script type="text/javascript">
    CARBON.showErrorDialog('<%=e.getMessage()%>', function () {
        location.href = "../admin/index.jsp";
    });
</script>
<%
    }
%>
<fmt:bundle basename="org.wso2.carbon.identity.certificateauthority.ui.i18n.Resources">
<carbon:breadcrumb
        label="identity.ca.certificate.list"
        resourceBundle="org.wso2.carbon.identity.certificateauthority.ui.i18n.Resources"
        topPage="true"
        request="<%=request%>"/>

<script type="text/javascript" src="../carbon/admin/js/breadcrumbs.js"></script>
<script type="text/javascript" src="../carbon/admin/js/cookies.js"></script>
<script type="text/javascript" src="resources/js/main.js"></script>
<!--Yahoo includes for dom event handling-->
<script src="../yui/build/yahoo-dom-event/yahoo-dom-event.js" type="text/javascript"></script>
<script src="../ca/js/create-basic-policy.js" type="text/javascript"></script>
<link href="css/ca.css" rel="stylesheet" type="text/css" media="all"/>

<script type="text/javascript">

    var allCertificatesSelected = false;

    function getSelectedStatusType() {
        var comboBox = document.getElementById("statusTypeFilter");
        var statusTypeFilter = comboBox[comboBox.selectedIndex].value;
        location.href = 'certificate-list-view.jsp?statusTypeFilter=' + statusTypeFilter;
    }
    function getSelectedReason() {
        var comboBox = document.getElementById("selectedReason");
        var selectedReason = comboBox[comboBox.selectedIndex].value;
        location.href = 'certificate-list-view.jsp?selectedReason=' + selectedReason;
    }

    function searchCertificates() {
        document.searchForm.submit();
    }
    function download(serialNo) {

    }
    function revoke(serialNo) {

    }
    function resetVars() {
        allCertificatesSelected = false;

        var isSelected = false;
        if (document.certificateForm.certificates[0] != null) {
            for (var j = 0; j < document.certificateForm.certificates.length; j++) {
                if (document.certificateForm.certificates[j].checked) {
                    isSelected = true;
                }
            }
        } else if (document.certificateForm.certificates != null) {
            if (document.certificateForm.certificates.checked) {
                isSelected = true;
            }
        }
        return false;
    }

    function revokeCertificates() {
        var selected = false;
        if (document.certificateForm.certificates[0] != null) { // there is more than 1 policy
            for (var j = 0; j < document.certificateForm.certificates.length; j++) {
                selected = document.certificateForm.certificates[j].checked;
                if (selected) break;
            }
        } else if (document.certificateForm.certificates != null) { // only 1 policy
            selected = document.certificateForm.certificates.checked;
        }
        if (!selected) {
            CARBON.showInfoDialog('<fmt:message key="select.certificates.to.be.revoked"/>');
            return;
        }
        if (allCertificatesSelected) {
            CARBON.showConfirmationDialog("<fmt:message key="revoke.all.certificates.prompt"/>", function () {
                document.certificateForm.action = "certificate-actions.jsp";
                document.certificateForm.submit();
            });
        } else {
            CARBON.showConfirmationDialog("<fmt:message key="revoke.certificates.on.page.prompt"/>", function () {
                document.certificateForm.action = "certificate-actions.jsp";
                document.certificateForm.submit();
            });
        }
    }

    function selectAllInThisPage(isSelected) {

        allCertificatesSelected = false;
        if (document.certificateForm.certificates != null &&
                document.certificateForm.certificates[0] != null) { // there is more than 1 service
            if (isSelected) {
                for (var j = 0; j < document.certificateForm.certificates.length; j++) {
                    document.certificateForm.certificates[j].checked = true;
                }
            } else {
                for (j = 0; j < document.certificateForm.certificates.length; j++) {
                    document.certificateForm.certificates[j].checked = false;
                }
            }
        } else if (document.certificateForm.certificates != null) { // only 1 service
            document.certificateForm.certificates.checked = isSelected;
        }
        return false;
    }

    function viewCertificate(serialNo) {
        location.href = "view-certificate.jsp?from=list&view=true&serialNo=" + serialNo;
    }

    function downloadCertificate(serialNo){
        location.href = "/ca/certificate/download/"+serialNo+".crt";
    }

</script>

<div id="middle">

    <h2><fmt:message key="identity.ca.certificate.list"/></h2>

    <div id="workArea">

        <form action="certificate-list-view.jsp" name="searchForm" method="post">
            <table id="searchTable" name="searchTable" class="styledLeft" style="border:0;
                                                !important margin-top:10px;margin-bottom:10px;">
                <tr>
                    <td>
                        <table style="border:0; !important">
                            <tbody>
                            <tr style="border:0; !important">

                                <td style="border:0; !important">
                                    <nobr>
                                        <fmt:message key="cert.type"/>
                                        <select name="statusTypeFilter" id="statusTypeFilter"
                                                onchange="getSelectedStatusType();">
                                            <%
                                                if (statusTypeFilter
                                                        .equals(CaUiConstants.STATUS_ALL)) {
                                            %>
                                            <option value="ALL" selected="selected"><fmt:message
                                                    key="all"/></option>
                                            <%
                                            } else {
                                            %>
                                            <option value="ALL"><fmt:message key="all"/></option>
                                            <%
                                                }
                                                for (CertificateStatus status : CertificateStatus
                                                        .values()) {
                                                    if (statusTypeFilter.equals(status.toString())) {
                                            %>
                                            <option value="<%= status.toString()%>"
                                                    selected="selected"><%=
                                            status.toString()%>
                                            </option>
                                            <%
                                            } else {
                                            %>
                                            <option value="<%= status.toString()%>"><%= status
                                                    .toString()%>
                                            </option>
                                            <%
                                                    }
                                                }
                                            %>
                                        </select>
                                        &nbsp;&nbsp;&nbsp;
                                        <fmt:message key="cert.search"/>
                                        <input type="text" name="certSearchString"
                                               value="<%= certSearchString != null? certSearchString
                                           :CaUiConstants.SEARCH_STRING_ANY%>"/>&nbsp;
                                    </nobr>
                                </td>
                                <td style="border:0; !important">
                                    <a class="icon-link" href="#"
                                       style="background-image: url(images/search.gif);"
                                       onclick="searchCertificates(); return false;"
                                       alt="<fmt:message key="search"/>"></a>
                                </td>
                            </tr>
                            </tbody>
                        </table>
                    </td>
                </tr>
                <tr>

                </tr>
            </table>
        </form>


        <form action="" name="certificateForm" method="post">
            <input type="hidden" name="action" value="revoke-multiple"/>
            <table style="border:0; !important">
                <tbody>
                <tr style="border:0; !important">

                    <td style="border:0; !important">
                        <nobr>
                            <fmt:message key="revoke.reason"/>
                            <select name="selectedReason" id="selectedReason">
                                <%
                                    for (RevokeReason reason : RevokeReason.values()) {
                                        if (reason == CaUiConstants.DEFAULT_REVOKE_REASON) {
                                %>
                                <option value="<%= reason.toString()%>" selected="selected"><%=
                                reason.getDisplayName()%>
                                </option>
                                <%
                                } else {
                                %>
                                <option value="<%= reason.toString()%>"><%= reason
                                        .getDisplayName()%>
                                </option>
                                <%
                                        }
                                    }
                                %>
                            </select>
                        </nobr>
                    </td>
                    <td>
                        <a onclick="revokeCertificates();return false;"
                           href="#" style="background-image: url(images/up.gif);"
                           class="icon-link">
                            <fmt:message key='revoke.selected'/></a>
                    </td>
                </tr>
                <tr>
                    <td>
                        <a style="cursor: pointer;"
                           onclick="selectAllInThisPage(true);return false;"
                           href="#"><fmt:message key="selectAllInPage"/></a>
                        &nbsp;<b>|</b>&nbsp;
                        <a style="cursor: pointer;"
                           onclick="selectAllInThisPage(false);return false;"
                           href="#"><fmt:message key="selectNone"/></a>
                    </td>
                </tr>
                </tbody>
            </table>
            <%
                if (certificatesToDisplay == null) {
            %>

            <fmt:message key="no.cert.available"/>
            <%
            } else {
            %>
            <table style="width: 100%" id="dataTable" class="styledLeft">
                <thead>
                <tr>
                    <th></th>
                    <th><fmt:message key='serial.No'/></th>
                    <th><fmt:message key='user'/></th>
                    <th><fmt:message key='issued.date'/></th>
                    <th><fmt:message key='expiry.date'/></th>
                    <th><fmt:message key='status'/></th>
                    <th><fmt:message key='download'/></th>
                    <th><fmt:message key='view.certificate'/></th>
                </tr>
                </thead>
                <%

                    for (CertificateInfo certificate : certificatesToDisplay) {
                        if (certificate != null) {

                %>
                <tr>
                    <td width="10px" style="text-align:center; !important">
                        <input type="checkbox" name="certificates"
                               value="<%=certificate.getSerialNo()%>"
                               onclick="resetVars()" class="chkBox"/>
                    </td>
                    <td width="20%"><%=certificate.getSerialNo()%>
                    </td>
                    <td width="20%"><%=certificate.getUsername()%>
                    </td>
                    <td><%=certificate.getIssuedDate()%>
                    </td>
                    <td><%=certificate.getExpiryDate()%>
                    </td>
                    <td><%=certificate.getStatus()%>
                    </td>

                    <td>
                        <nobr>
                            <a onclick="downloadCertificate('<%=certificate.getSerialNo()%>');"
                               href="#"
                               class="icon-link" style="background-image:url(images/download.gif);">
                                <fmt:message key="download"/>
                            </a>
                        </nobr>
                    </td>
                    <td>
                        <a onclick="viewCertificate('<%=certificate.getSerialNo()%>');return false;"
                           href="#" style="background-image: url(images/up.gif);"
                           class="icon-link">
                            <fmt:message key='view.certificate'/></a>
                    </td>
                </tr>
                <%
                            }
                        }

                    }
                %>

            </table>
            <carbon:paginator pageNumber="<%=pageNumberInt%>"
                              numberOfPages="<%=numberOfPages%>"
                              page="certificate-list-view.jsp"
                              pageNumberParameterName="pageNumber"
                              parameters="<%=paginationValue%>"
                              resourceBundle="org.wso2.carbon.identity.certificateauthority.ui.i18n.Resources"
                              prevKey="prev" nextKey="next"/>
        </form>
    </div>
</div>
</fmt:bundle>