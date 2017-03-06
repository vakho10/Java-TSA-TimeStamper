package ge.vakho.source;

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

import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;

public class TimeStamperBuilder
{
    private URL tsaUrl;
    private Proxy proxy;
    private byte[] data;
    private String requestMethod;

    /**
     * Set TSA's URL
     */
    public TimeStamperBuilder setTsaUrl(String tsaUrl) throws MalformedURLException
    {
        this.tsaUrl = new URL(tsaUrl);
        return this;
    }

    /**
     * Set proxy
     */
    public TimeStamperBuilder setProxy(String address, int port, String username, String password)
    {
        this.proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(address, port));
        if (username != null && password != null)
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

    /**
     * Set data
     */
    public TimeStamperBuilder setData(byte[] data)
    {
        this.data = data;
        return this;
    }

    /**
     * Set HTTP request method.
     */
    public TimeStamperBuilder setRequestMethod(String method)
    {
        this.requestMethod = method;
        return this;
    }

    /**
     * Builds and returns new instance of TimeStamper object.
     */
    public TimeStamper build()
    {
        TimeStamper stamper = new TimeStamperBuilder().new ConcreteTimeStamper();
        stamper.setTsaUrl(tsaUrl);
        stamper.setProxy(proxy);
        stamper.setRequestMethod(requestMethod);
        stamper.setData(data);
        return stamper;
    }

    private class ConcreteTimeStamper implements TimeStamper
    {
        private URL tsaUrl;
        private Proxy proxy;
        private byte[] data;
        private String requestMethod;

        @Override
        public String getRequestMethod()
        {
            return requestMethod;
        }

        @Override
        public void setRequestMethod(String requestMethod)
        {
            this.requestMethod = requestMethod;
        }

        @Override
        public void setTsaUrl(URL tsaUrl)
        {
            this.tsaUrl = tsaUrl;
        }

        @Override
        public void setProxy(Proxy proxy)
        {
            this.proxy = proxy;
        }

        @Override
        public void setData(byte[] data)
        {
            this.data = data;
        }

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
        public TimeStampResponse timestamp() throws Exception
        {
            // Generate timestamp request object
            TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
            OutputStream out = null;
            tsqGenerator.setCertReq(false);

            // Calculate data digest
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
            messageDigest.update(data);
            byte[] digest = messageDigest.digest();

            TimeStampRequest request = tsqGenerator.generate(TSPAlgorithms.SHA1, digest);
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
            if (data == null || data.length == 0)
            {
                throw new IllegalArgumentException("The data mustn't be empty!");
            }
            setData(data);
            return timestamp();
        }
    }
}
