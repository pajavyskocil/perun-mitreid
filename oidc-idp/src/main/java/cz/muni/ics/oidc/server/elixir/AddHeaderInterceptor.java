package cz.muni.ics.oidc.server.elixir;

import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

import java.io.IOException;

class AddHeaderInterceptor implements ClientHttpRequestInterceptor {

	private final String header;
	private final String value;

	AddHeaderInterceptor(String header, String value) {
		this.header = header;
		this.value = value;
	}

	@Override
	public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {
		request.getHeaders().add(header, value);
		return execution.execute(request, body);
	}
}
