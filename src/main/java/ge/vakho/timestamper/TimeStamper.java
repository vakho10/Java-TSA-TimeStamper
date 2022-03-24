package ge.vakho.timestamper;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.Callable;

public class TimeStamper implements Callable<TimeStampResponse> {

    private URL tsaUrl;
    private byte[] data;
    private String requestMethod;
    private MessageDigest messageDigest;
    private ASN1ObjectIdentifier digestAlgAsn1;

    public URL getTsaUrl() {
        return tsaUrl;
    }

    public byte[] getData() {
        return data;
    }

    public String getRequestMethod() {
        return requestMethod;
    }

    public MessageDigest getMessageDigest() {
        return messageDigest;
    }

    public ASN1ObjectIdentifier getDigestAlgAsn1() {
        return digestAlgAsn1;
    }

    public TimeStampResponse timestamp() throws IOException, TSPException {
        TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
        tsqGenerator.setCertReq(true);

        // Calculate data digest
        messageDigest.update(data);
        byte[] digest = messageDigest.digest();

        TimeStampRequest request = tsqGenerator.generate(digestAlgAsn1, digest);
        byte[] requestBytes = request.getEncoded();

        HttpURLConnection con = (HttpURLConnection) tsaUrl.openConnection();
        con.setDoOutput(true);
        con.setDoInput(true);
        con.setRequestMethod(requestMethod);
        con.setRequestProperty("Content-type", "application/timestamp-query");
        con.setRequestProperty("Content-length", String.valueOf(requestBytes.length));
        try (OutputStream out = con.getOutputStream()) {
            out.write(requestBytes);
        }

        if (con.getResponseCode() != HttpURLConnection.HTTP_OK) {
            throw new IOException("Received HTTP error: " + con.getResponseCode() + " - " + con.getResponseMessage());
        }

        byte[] responseBytes;
        try (InputStream inputStream = con.getInputStream()) {
            responseBytes = IOUtils.toByteArray(inputStream);
        }

        TimeStampResponse resp = new TimeStampResponse(responseBytes);
        resp.validate(request);
        return resp;
    }

    @Override
    public TimeStampResponse call() throws Exception {
        return timestamp();
    }

    public static class Builder {

        private TimeStamper timeStamper = new TimeStamper();

        public Builder requestMethod(String requestMethod) {
            timeStamper.requestMethod = requestMethod;
            return this;
        }

        public Builder tsaUrl(String url) throws MalformedURLException {
            timeStamper.tsaUrl = URI.create(url).toURL();
            return this;
        }

        public Builder data(byte[] data) {
            timeStamper.data = data;
            return this;
        }

        public Builder messageDigest(String algorithm, ASN1ObjectIdentifier digestAlgAsn1) throws NoSuchAlgorithmException {
            timeStamper.messageDigest = MessageDigest.getInstance(algorithm);
            timeStamper.digestAlgAsn1 = digestAlgAsn1;
            return this;
        }

        public TimeStamper build() {
            return timeStamper;
        }
    }
}
