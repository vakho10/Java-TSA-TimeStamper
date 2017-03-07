package ge.vakho.timestamper;

import java.net.Proxy;
import java.net.URL;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
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
    
    void setMessageDigest(String algorithm, ASN1ObjectIdentifier digestAlgAsn1) throws NoSuchAlgorithmException;
    
    Object[] getMessageDigest();

    TimeStampResponse timestamp() throws Exception;

    TimeStampResponse timestamp(byte[] data) throws Exception;
}
