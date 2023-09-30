import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import der.tools.DEREncoder;

/**
 * Class that produces a DER encoded byte array based on a passed in encoding.
 */
public class DEREncoderDemo
{
    private static byte[] baseCert = Base64.getDecoder().decode(
        "MIIDbDCCAtWgAwIBAgIBADANBgkqhkiG9w0BAQQFADCBtzELMAkGA1UEBhMCQVUx"
            + "ETAPBgNVBAgTCFZpY3RvcmlhMRgwFgYDVQQHEw9Tb3V0aCBNZWxib3VybmUxGjAY"
            + "BgNVBAoTEUNvbm5lY3QgNCBQdHkgTHRkMR4wHAYDVQQLExVDZXJ0aWZpY2F0ZSBB"
            + "dXRob3JpdHkxFTATBgNVBAMTDENvbm5lY3QgNCBDQTEoMCYGCSqGSIb3DQEJARYZ"
            + "d2VibWFzdGVyQGNvbm5lY3Q0LmNvbS5hdTAeFw0wMDA2MDIwNzU1MzNaFw0wMTA2"
            + "MDIwNzU1MzNaMIG3MQswCQYDVQQGEwJBVTERMA8GA1UECBMIVmljdG9yaWExGDAW"
            + "BgNVBAcTD1NvdXRoIE1lbGJvdXJuZTEaMBgGA1UEChMRQ29ubmVjdCA0IFB0eSBM"
            + "dGQxHjAcBgNVBAsTFUNlcnRpZmljYXRlIEF1dGhvcml0eTEVMBMGA1UEAxMMQ29u"
            + "bmVjdCA0IENBMSgwJgYJKoZIhvcNAQkBFhl3ZWJtYXN0ZXJAY29ubmVjdDQuY29t"
            + "LmF1MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDgs5ptNG6Qv1ZpCDuUNGmv"
            + "rhjqMDPd3ri8JzZNRiiFlBA4e6/ReaO1U8ASewDeQMH6i9R6degFdQRLngbuJP0s"
            + "xcEE+SksEWNvygfzLwV9J/q+TQDyJYK52utb++lS0b48A1KPLwEsyL6kOAgelbur"
            + "ukwxowprKUIV7Knf1ajetQIDAQABo4GFMIGCMCQGA1UdEQQdMBuBGXdlYm1hc3Rl"
            + "ckBjb25uZWN0NC5jb20uYXUwDwYDVR0TBAgwBgEB/wIBADA2BglghkgBhvhCAQ0E"
            + "KRYnbW9kX3NzbCBnZW5lcmF0ZWQgY3VzdG9tIENBIGNlcnRpZmljYXRlMBEGCWCG"
            + "SAGG+EIBAQQEAwICBDANBgkqhkiG9w0BAQQFAAOBgQCsGvfdghH8pPhlwm1r3pQk"
            + "msnLAVIBb01EhbXm2861iXZfWqGQjrGAaA0ZpXNk9oo110yxoqEoSJSzniZa7Xtz"
            + "soTwNUpE0SLHvWf/SlKdFWlzXA+vOZbzEv4UmjeelekTm7lc01EEa5QRVzOxHFtQ"
            + "DhkaJ8VqOMajkQFma2r9iA==");

    private static byte[] cert_multiv_dn_ber = Base64.getDecoder().decode(
        "MIICjzCCAjmgAwIBAgIBATANBgkqhkiG9w0BAQQFADCBrTELMAkGA1UEBhMCQVUxKDAmBgNVBAoMH1RoZSBMZWdpb24gb2YgdGhlIEJvdW5jeSBDYXN0bGUxEjAQBgNVBAcMCU1lbGJvdXJuZTERMA8GA1UECAwIVmljdG9yaWExTTAtBgkqhkiG9w0BCQEWIGZlZWRiYWNrLWNyeXB0b0Bib3VuY3ljYXN0bGUub3JnMBwGA1UEBRMVQ1ZSOjEyMzQ1Njc4LVVJRDoxMTExMB4XDTIzMDcyMDA3MzA1NFoXDTIzMDcyMDA3MzIzNFowga0xCzAJBgNVBAYTAkFVMSgwJgYDVQQKDB9UaGUgTGVnaW9uIG9mIHRoZSBCb3VuY3kgQ2FzdGxlMRIwEAYDVQQHDAlNZWxib3VybmUxETAPBgNVBAgMCFZpY3RvcmlhMU0wHAYDVQQFExVDVlI6MTIzNDU2NzgtVUlEOjExMTEwLQYJKoZIhvcNAQkBFiBmZWVkYmFjay1jcnlwdG9AYm91bmN5Y2FzdGxlLm9yZzBaMA0GCSqGSIb3DQEBAQUAA0kAMEYCQQC0p+RhcFdPFqlwgrIr5YtqKmKXmEGb4ShypL26Ymz66ZAPdqv7EhOdzl3lZWT6srZUMWWgQMYGiHQg4z2R7X7XAgERo0QwQjAOBgNVHQ8BAf8EBAMCAAEwEgYDVR0lAQH/BAgwBgYEVR0lADAcBgNVHREBAf8EEjAQgQ50ZXN0QHRlc3QudGVzdDANBgkqhkiG9w0BAQQFAANBAIhylDesUsTXE5nOV5hnGxnIamkLXNqJGBvNTOboDnxKF7bEi6mswBhk7zEc9aLnX5lH65jVJ6ZVUxvownx8jYU=");

    private static byte[] cert_multiv_dn_der = Base64.getDecoder().decode(
        "MIICjzCCAjmgAwIBAgIBATANBgkqhkiG9w0BAQQFADCBrTELMAkGA1UEBhMCQVUxKDAmBgNVBAoMH1RoZSBMZWdpb24gb2YgdGhlIEJvdW5jeSBDYXN0bGUxEjAQBgNVBAcMCU1lbGJvdXJuZTERMA8GA1UECAwIVmljdG9yaWExTTAcBgNVBAUTFUNWUjoxMjM0NTY3OC1VSUQ6MTExMTAtBgkqhkiG9w0BCQEWIGZlZWRiYWNrLWNyeXB0b0Bib3VuY3ljYXN0bGUub3JnMB4XDTIzMDcyMDA3MzA1NFoXDTIzMDcyMDA3MzIzNFowga0xCzAJBgNVBAYTAkFVMSgwJgYDVQQKDB9UaGUgTGVnaW9uIG9mIHRoZSBCb3VuY3kgQ2FzdGxlMRIwEAYDVQQHDAlNZWxib3VybmUxETAPBgNVBAgMCFZpY3RvcmlhMU0wHAYDVQQFExVDVlI6MTIzNDU2NzgtVUlEOjExMTEwLQYJKoZIhvcNAQkBFiBmZWVkYmFjay1jcnlwdG9AYm91bmN5Y2FzdGxlLm9yZzBaMA0GCSqGSIb3DQEBAQUAA0kAMEYCQQC0p+RhcFdPFqlwgrIr5YtqKmKXmEGb4ShypL26Ymz66ZAPdqv7EhOdzl3lZWT6srZUMWWgQMYGiHQg4z2R7X7XAgERo0QwQjAOBgNVHQ8BAf8EBAMCAAEwEgYDVR0lAQH/BAgwBgYEVR0lADAcBgNVHREBAf8EEjAQgQ50ZXN0QHRlc3QudGVzdDANBgkqhkiG9w0BAQQFAANBAIhylDesUsTXE5nOV5hnGxnIamkLXNqJGBvNTOboDnxKF7bEi6mswBhk7zEc9aLnX5lH65jVJ6ZVUxvownx8jYU=");

    public static void main(String[] args)
        throws Exception
    {
        DEREncoder derEnc = new DEREncoder(DEREncoder.LENGTHS | DEREncoder.SORT_SETS);

        byte[] derOut = derEnc.toDER(baseCert);

        System.out.println(Arrays.equals(derOut, baseCert));

        derOut = derEnc.toDER(cert_multiv_dn_der);

        System.out.println(Arrays.equals(derOut, cert_multiv_dn_der));

        derOut = derEnc.toDER(cert_multiv_dn_ber);

        System.out.println(Arrays.equals(derOut, cert_multiv_dn_der));

        derOut = derEnc.toDER(cert_multiv_dn_ber);

        System.out.println(Arrays.equals(derOut, cert_multiv_dn_der));
        System.out.println(Arrays.equals(cert_multiv_dn_ber, cert_multiv_dn_der));
    }
}
