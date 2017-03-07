# Java TSA TimeStamper

Simple Java project that uses Bouncy Castle API to send TimeStamp request (to free TSA).

## Usage

```java
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampResponse;

public class Main
{
    public static void main(String[] args) throws Exception
    {
        // Construct TimeStamper object using builder class...
        TimeStamper timeStamper = new TimeStamperBuilder()
                .setProxy("192.168.253.30", 8080)
                .setRequestMethod("GET")
                .setDigestAlgorithm("SHA-1", TSPAlgorithms.SHA1)
                .setTsaUrl("http://timestamp.comodoca.com/authenticode")
                .setData("Some!".getBytes())
                .build();

        // Call timestamp method to get TimeStampResponse.
        TimeStampResponse response = timeStamper.timestamp();

        // Print or use it anywhere...
        System.out.println(response.getTimeStampToken().getTimeStampInfo().getGenTime());
    }
}
```
