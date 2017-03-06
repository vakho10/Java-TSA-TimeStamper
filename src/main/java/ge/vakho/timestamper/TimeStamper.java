package ge.vakho.timestamper;

import java.net.Proxy;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.tsp.TimeStampResponse;

public interface TimeStamper
{
    void setTsaUrl(URL tsaUrl);

    URL getTsaUrl();

    void setProxy(Proxy proxy);

    Proxy getProxy();

    void setData(byte[] data);

    byte[] getData();

    void setRequestMethod(String requestMethod);

    String getRequestMethod();
    
    void setMessageDigest(String algorithm) throws NoSuchAlgorithmException;
    
    MessageDigest getMessageDigest();

    TimeStampResponse timestamp() throws Exception;

    TimeStampResponse timestamp(byte[] data) throws Exception;
}
