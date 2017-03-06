# Java-TSA-TimeStamper

Simple Java project that uses Bouncy Castle API to send TimeStamp request (to free TSA).

## Usage

```java
public static void main(String[] args) throws Exception 
{
	TimeStamper timeStamper = new TimeStamperBuilder()
                                    .setRequestMethod("GET")
                                    .setDigestAlgorithm("SHA-256")
                                    .setTsaUrl("http://timestamp.comodoca.com/authenticode")
                                    .setData("Some!".getBytes())
                                    .build();

	TimeStampResponse response = timeStamper.timestamp();

	System.out.println(response.getTimeStampToken().getTimeStampInfo().getGenTime());
}
```