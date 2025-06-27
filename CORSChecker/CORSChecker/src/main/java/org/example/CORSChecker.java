package org.example;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;


public class CORSChecker implements BurpExtension, HttpHandler {

    private MontoyaApi api;

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        this.api = montoyaApi;
        api.extension().setName("CORS Checker");
        api.logging().logToOutput("This is a plugin to check for CORS misconfigurations");
        api.http().registerHttpHandler(this);
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent httpRequestToBeSent) {
        HttpRequest cors = httpRequestToBeSent.withAddedHeader("Origin", "null");
        return RequestToBeSentAction.continueWith(cors);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived httpResponseReceived) {
        String allowOrigin = httpResponseReceived.headerValue("Access-Control-Allow-Origin");
        String allowCredentials = httpResponseReceived.headerValue("Access-Control-Allow-Credentials");

        if ("null".equalsIgnoreCase(allowOrigin) && "true".equalsIgnoreCase(allowCredentials)) {
            // Log to Burp's output tab
            api.logging().logToOutput("!! Potential CORS misconfig detected: \n" +
                    "Access-Control-Allow-Origin: null\n" +
                    "Access-Control-Allow-Credentials: true\n" +
                    "URL: " +
                    httpResponseReceived.initiatingRequest().url());
        }

        return ResponseReceivedAction.continueWith(httpResponseReceived);
    }


}
