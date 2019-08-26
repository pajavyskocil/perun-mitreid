package cz.muni.ics.oidc.server.filters;

import com.google.common.base.Strings;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.sql.DataSource;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.time.LocalDate;


/**
 * Filter for collecting data about login.
 *
 * @author Dominik Baránek <0Baranek.dominik0@gmail.com>
 */
public class ProxyStatisticsFilter extends GenericFilterBean {

	private final static Logger log = LoggerFactory.getLogger(ProxyStatisticsFilter.class);

	/**
	 * Name of the ServletRequest attribute which contains IdP's name.
	 */
	private String idpNameAttributeName;

	/**
	 * Name of the ServletRequest attribute which contains IdP's entityID.
	 */
	private String idpEntityIdAttributeName;

	@Autowired
	private OAuth2RequestFactory authRequestFactory;

	@Autowired
	private ClientDetailsEntityService clientService;

	@Autowired
	private DataSource mitreIdStats;

	private static final String REQ_PATTERN = "/authorize";
	private RequestMatcher requestMatcher = new AntPathRequestMatcher(REQ_PATTERN);

	private String statisticsTableName;
	private String identityProvidersMapTableName;
	private String serviceProvidersMapTableName;

	public void setStatisticsTableName(String statisticsTableName) {
		this.statisticsTableName = statisticsTableName;
	}

	public void setIdentityProvidersMapTableName(String identityProvidersMapTableName) {
		this.identityProvidersMapTableName = identityProvidersMapTableName;
	}

	public void setServiceProvidersMapTableName(String serviceProvidersMapTableName) {
		this.serviceProvidersMapTableName = serviceProvidersMapTableName;
	}

	public void setIdpNameAttributeName(String idpNameAttributeName) {
		this.idpNameAttributeName = idpNameAttributeName;
	}

	public void setIdpEntityIdAttributeName(String idpEntityIdAttributeName) {
		this.idpEntityIdAttributeName = idpEntityIdAttributeName;
}

	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;

		ClientDetailsEntity client = FiltersUtils.extractClient(requestMatcher, request, authRequestFactory, clientService);
		if (client == null) {
			log.debug("Could not fetch client, skip to next filter");
			chain.doFilter(req, res);
			return;
		}

		String clientIdentifier = client.getClientId();
		String clientName = client.getClientName();

		if (Strings.isNullOrEmpty((String) request.getAttribute(idpEntityIdAttributeName))) {
			log.warn("Attribute '" + idpEntityIdAttributeName + "' is null or empty, skip to next filter");
			chain.doFilter(req, res);
			return;
		}

		String idpEntityIdFromRequest = (String) request.getAttribute(idpEntityIdAttributeName);
		String idpNameFromRequest = (String) request.getAttribute(idpNameAttributeName);

		String idpEntityId = changeEncodingOfParam(idpEntityIdFromRequest,
				StandardCharsets.ISO_8859_1, StandardCharsets.UTF_8);
		String idpName = changeEncodingOfParam(idpNameFromRequest,
				StandardCharsets.ISO_8859_1, StandardCharsets.UTF_8);

		insertLogin(idpEntityId, idpName, clientIdentifier, clientName);

		chain.doFilter(req, res);
	}

	private void insertLogin(String idpEntityId, String idpName, String spIdentifier, String spName) {
		LocalDate date = LocalDate.now();

		String queryStats = "INSERT INTO " + statisticsTableName + "(year, month, day, sourceIdp, service, count)" +
				" VALUES(?,?,?,?,?,'1') ON DUPLICATE KEY UPDATE count = count + 1";

		String queryIdPMap = "INSERT INTO " + identityProvidersMapTableName + "(entityId, name)" +
				" VALUES (?, ?) ON DUPLICATE KEY UPDATE name = ?";

		String queryServiceMap = "INSERT INTO " + serviceProvidersMapTableName + "(identifier, name)" +
				" VALUES (?, ?) ON DUPLICATE KEY UPDATE name = ?";

		try (Connection c = mitreIdStats.getConnection()) {
			try (PreparedStatement preparedStatement = c.prepareStatement(queryStats)) {
				preparedStatement.setInt(1, date.getYear());
				preparedStatement.setInt(2, date.getMonthValue());
				preparedStatement.setInt(3, date.getDayOfMonth());
				preparedStatement.setString(4, idpEntityId);
				preparedStatement.setString(5, spIdentifier);
				preparedStatement.execute();
			}
			if (!Strings.isNullOrEmpty(idpName)) {
				try (PreparedStatement preparedStatement = c.prepareStatement(queryIdPMap)) {
					preparedStatement.setString(1, idpEntityId);
					preparedStatement.setString(2, idpName);
					preparedStatement.setString(3, idpName);
					preparedStatement.execute();
				}
			}
			if (!Strings.isNullOrEmpty(spName)) {
				try (PreparedStatement preparedStatement = c.prepareStatement(queryServiceMap)) {
					preparedStatement.setString(1, spIdentifier);
					preparedStatement.setString(2, spName);
					preparedStatement.setString(3, spName);
					preparedStatement.execute();
				}
			}
			log.debug("The login log was successfully stored into database: ({},{},{},{})", idpEntityId, idpName, spIdentifier, spName);
		} catch (SQLException ex) {
			log.warn("Statistics weren't updated due to SQLException.");
			log.debug("SQLException ({})", ex);
		}
	}

	private String changeEncodingOfParam(String original, Charset source, Charset destination) {
		if (original != null && !original.isEmpty()) {
			byte[] sourceBytes = original.getBytes(source);
			return new String(sourceBytes, destination);
		}

		return null;
	}
}
