<%@ page contentType="text/html; charset=utf-8" pageEncoding="utf-8" trimDirectiveWhitespaces="true" %>
<%@ taglib prefix="authz" uri="http://www.springframework.org/security/tags"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>
<%@ taglib prefix="o" tagdir="/WEB-INF/tags"%>
<%@ taglib prefix="t" tagdir="/WEB-INF/tags/common"%>
<%@ taglib prefix="elixir" tagdir="/WEB-INF/tags/elixir" %>
<%@ taglib prefix="cesnet" tagdir="/WEB-INF/tags/cesnet" %>
<%@ taglib prefix="bbmri" tagdir="/WEB-INF/tags/bbmri" %>
<%@ taglib prefix="ceitec" tagdir="/WEB-INF/tags/ceitec" %>
<%@ taglib prefix="europdx" tagdir="/WEB-INF/tags/europdx" %>

<c:choose>
    <c:when test="${theme eq 'default'}">
        <o:header title="${title}"/>
    </c:when>
    <c:otherwise>
        <t:header title="${title}" reqURL="${reqURL}"/>
    </c:otherwise>
</c:choose>
<div id="content">
    <div class="error_message" style="word-wrap: break-word;">
        <c:forEach var="contactIter" items="${client.contacts}" end="0">
            <c:set var="contact" value="${contactIter}" />
        </c:forEach>
        <c:if test="${empty contact}">
            <c:choose>
                <c:when test="${theme eq 'elixir'}">
                    <c:set var="contact" value="aai-contact@elixir-europe.org"/>
                </c:when>
                <c:when test="${theme eq 'cesnet'}">
                    <c:set var="contact" value="login@cesnet.cz"/>
                </c:when>
                <c:when test="${theme eq 'ceitec'}">
                    <c:set var="contact" value="idm@ics.muni.cz"/>
                </c:when>
                <c:when test="${theme eq 'bbmri-eric'}">
                    <c:set var="contact" value="aai@helpdesk.bbmri-eric.eu"/>
                </c:when>
                <c:when test="${theme eq 'europdx'}">
                    <c:set var="contact" value="contact@europdx.eu"/>
                </c:when>
            </c:choose>
        </c:if>
        <h1>${langProps['403_header']}</h1>
        <p>${langProps['403_text']}&#32;${fn:escapeXml(client.clientName)}
            <br/>
            <c:if test="${not empty client.clientUri}">
                ${langProps['403_informationPage']}&#32;
                <a href="${fn:escapeXml(client.clientUri)}">
                    ${fn:escapeXml(client.clientUri)}
                </a>
            </c:if>
        </p>

        <p>${langProps['403_contactSupport']}&#32;
           <a href="mailto:${contact}?subject=${langProps["403_subject"]} ${fn:escapeXml(client.clientName)}">
               ${fn:escapeXml(contact)}
           </a>
        </p>
    </div>
</div>
</div><!-- ENDWRAP -->
<c:choose>
    <c:when test="${theme eq 'elixir'}">
        <elixir:footer />
    </c:when>
    <c:when test="${theme eq 'cesnet'}">
        <cesnet:footer />
    </c:when>
    <c:when test="${theme eq 'bbmri-eric'}">
        <bbmri:footer />
    </c:when>
    <c:when test="${theme eq 'ceitec'}">
        <ceitec:footer />
    </c:when>
    <c:when test="${theme eq 'europdx'}">
        <europdx:footer />
    </c:when>
    <c:otherwise>
        <o:footer />
    </c:otherwise>
</c:choose>