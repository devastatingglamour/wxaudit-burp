package burp;
public interface IHttpRequestResponse {
    byte[] getRequest();
    byte[] getResponse();
    java.net.URL getUrl();
}
