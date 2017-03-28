package ge.vakho.timestamper;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;

public abstract class TimeStamper
{
    public abstract URL getTsaUrl();

    public abstract Proxy getProxy();

    public abstract byte[] getData();

    public abstract String getRequestMethod();

    public abstract Object[] getMessageDigest();

    public abstract TimeStampResponse timestamp() throws Exception;

    public abstract TimeStampResponse timestamp(byte[] data) throws Exception;

    public static class Builder
    {
        private ConcreteTimeStamper concreteTimeStamper;

        public Builder()
        {
            concreteTimeStamper = new ConcreteTimeStamper();
        }

        public Builder setRequestMethod(String requestMethod)
        {
            concreteTimeStamper.requestMethod = requestMethod;
            return this;
        }

        public Builder setTsaUrl(String url) throws MalformedURLException
        {
            concreteTimeStamper.tsaUrl = new URL(url);
            return this;
        }

        public Builder setProxy(String address, int port)
        {
            return setProxy(address, port, null, null);
        }

        public Builder setProxy(String address, int port, String username, String password)
        {
            concreteTimeStamper.proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(address, port));
            if (StringUtils.isNotEmpty(username) && StringUtils.isNotEmpty(password))
            {
                // Set default authentication
                Authenticator.setDefault(new Authenticator()
                {
                    @Override
                    public PasswordAuthentication getPasswordAuthentication()
                    {
                        return new PasswordAuthentication(username, password.toCharArray());
                    }
                });
            }
            return this;
        }

        public Builder setData(byte[] data)
        {
            concreteTimeStamper.data = data;
            return this;
        }

        public Builder setMessageDigest(String algorithm, ASN1ObjectIdentifier digestAlgAsn1) throws NoSuchAlgorithmException
        {
            concreteTimeStamper.messageDigest = MessageDigest.getInstance(algorithm);
            concreteTimeStamper.digestAlgAsn1 = digestAlgAsn1;
            return this;
        }

        public TimeStamper build() throws CloneNotSupportedException
        {
            return (TimeStamper) concreteTimeStamper.clone();
        }

        private static class ConcreteTimeStamper extends TimeStamper implements Cloneable
        {
            private URL tsaUrl;
            private Proxy proxy;
            private byte[] data;
            private String requestMethod;
            private MessageDigest messageDigest;
            private ASN1ObjectIdentifier digestAlgAsn1;

            @Override
            public URL getTsaUrl()
            {
                return tsaUrl;
            }

            @Override
            public Proxy getProxy()
            {
                return proxy;
            }

            @Override
            public byte[] getData()
            {
                return data;
            }

            @Override
            public String getRequestMethod()
            {
                return requestMethod;
            }

            @Override
            public Object[] getMessageDigest()
            {
                return new Object[] { messageDigest, digestAlgAsn1 };
            }

            @Override
            public TimeStampResponse timestamp() throws Exception
            {
                if (data == null || data.length == 0)
                {
                    throw new IllegalArgumentException("The data mustn't be empty!");
                }

                // Generate timestamp request object
                TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
                OutputStream out = null;
                tsqGenerator.setCertReq(true);

                // Calculate data digest
                messageDigest.update(data);
                byte[] digest = messageDigest.digest();

                TimeStampRequest request = tsqGenerator.generate(digestAlgAsn1, digest);
                byte[] requestBytes = request.getEncoded();

                HttpURLConnection con = (HttpURLConnection) tsaUrl.openConnection(proxy);
                con.setDoOutput(true);
                con.setDoInput(true);
                con.setRequestMethod(requestMethod);
                con.setRequestProperty("Content-type", "application/timestamp-query");
                con.setRequestProperty("Content-length", String.valueOf(requestBytes.length));
                out = con.getOutputStream();
                out.write(requestBytes);
                out.flush();

                if (con.getResponseCode() != HttpURLConnection.HTTP_OK)
                {
                    throw new IOException("Received HTTP error: " + con.getResponseCode() + " - " + con.getResponseMessage());
                }
                InputStream in = con.getInputStream();

                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                byte[] buffer = new byte[1024];
                int bytesRead = 0;
                while ((bytesRead = in.read(buffer, 0, buffer.length)) >= 0)
                {
                    baos.write(buffer, 0, bytesRead);
                }
                byte[] respBytes = baos.toByteArray();

                TimeStampResponse resp = new TimeStampResponse(respBytes);
                resp.validate(request);
                return resp;
            }

            @Override
            public TimeStampResponse timestamp(byte[] data) throws Exception
            {
                this.data = data;
                return timestamp();
            }

        }
    }
}
