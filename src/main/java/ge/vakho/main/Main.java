package ge.vakho.main;

import org.bouncycastle.tsp.TimeStampResponse;

import ge.vakho.source.TimeStamper;
import ge.vakho.source.TimeStamperBuilder;

public class Main
{
    public static void main(String[] args) throws Exception
    {
        TimeStamper timeStamper = new TimeStamperBuilder()
                                        // .setProxy()
                                        .setRequestMethod("GET")
                                        .setTsaUrl("http://timestamp.comodoca.com/authenticode")
                                        .setData("Dato is a very good person!".getBytes())
                                        .build();

        TimeStampResponse response = timeStamper.timestamp();

        System.out.println(response.getTimeStampToken().getTimeStampInfo().getGenTime());
    }
}
