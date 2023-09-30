package der.tools;

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


/**
 * Class that produces a DER encoded byte array based on a passed in encoding.
 */
public class DEREncoder
{
    /**
     * Flags are designed to be '|'ed together
     */
    public static final int NO_ENFORCEMENT = 0; // return bytes as is
    public static final int LENGTHS = 1; // enforce length encoding limitations
    public static final int SORT_SETS = 2; // sort sets correctly

    private final int enforcementFlags;

    public DEREncoder(int enforcementFlags)
    {
        this.enforcementFlags = enforcementFlags;
    }

    public byte[] toDER(byte[] input)
        throws IOException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(input);

        if (enforcementFlags == NO_ENFORCEMENT)
        {
            return input;
        }

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        process(bOut, input, 0);

        return bOut.toByteArray();
    }

    private int process(OutputStream out, byte[] data, int offset)
        throws IOException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(data, offset, data.length - offset);
        int baseTag = bIn.read();
        int flags = baseTag & 0xe0;
        int t = readTagNumber(bIn, baseTag & 0x1f);
        int l = readLength(bIn, data.length - offset);
        byte[] v = new byte[l];

        bIn.read(v);       // this will always read the full amount or fail as backed by byte array.

        int totalRead = data.length - offset - bIn.available();

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        if ((flags & BERTags.CONSTRUCTED) != 0)
        {
            int index = 0;
            switch (t)
            {
            case BERTags.SEQUENCE:
                while (index < v.length)
                {
                    index += process(bOut, v, index);
                }
                break;
            case BERTags.SET:
                List<byte[]> elements = new ArrayList<byte[]>();
                ByteArrayOutputStream eltOut = new ByteArrayOutputStream();
                while (index < v.length)
                {
                    index += process(eltOut, v, index);
                    elements.add(eltOut.toByteArray());
                    eltOut.reset();
                }
                if ((enforcementFlags & SORT_SETS) != 0)
                {
                    sort(elements);
                }
                for (byte[] encoding : elements)
                {
                    bOut.write(encoding);
                }
                break;
            default:
                if ((flags & BERTags.TAGGED) != 0)
                {
                    while (index < v.length)
                    {
                        index += process(bOut, v, index);
                    }
                }
                else
                {
                    throw new IllegalArgumentException("found constructed primitive");
                }
            }
        }
        else
        {
            bOut.write(v);
        }

        byte[] derResult = bOut.toByteArray();

        writeTag(out, flags, t);
        writeLength(out, derResult.length);
        out.write(derResult);

        return totalRead;
    }

    static int readTagNumber(InputStream s, int baseTag)
        throws IOException
    {
        int tag = baseTag;
        int tagNo = tag & 0x1f;

        //
        // with tagged object tag number is bottom 5 bits, or stored at the start of the content
        //
        if (tagNo == 0x1f)
        {
            int b = s.read();
            if (b < 31)
            {
                if (b < 0)
                {
                    throw new EOFException("EOF found inside tag value.");
                }
                throw new IOException("corrupted stream - high tag number < 31 found");
            }

            tagNo = b & 0x7f;

            // X.690-0207 8.1.2.4.2
            // "c) bits 7 to 1 of the first subsequent octet shall not all be zero."
            if (0 == tagNo)
            {
                throw new IOException("corrupted stream - invalid high tag number found");
            }

            while ((b & 0x80) != 0)
            {
                if ((tagNo >>> 24) != 0)
                {
                    throw new IOException("Tag number more than 31 bits");
                }

                tagNo <<= 7;

                b = s.read();
                if (b < 0)
                {
                    throw new EOFException("EOF found inside tag value.");
                }

                tagNo |= (b & 0x7f);
            }
        }

        return tagNo;
    }

    private static int readLength(InputStream s, int limit)
        throws IOException
    {
        int length = s.read();
        if (0 == (length >>> 7))
        {
            // definite-length short form
            return length;
        }
        if (0x80 == length)
        {
            // indefinite-length
            return -1;
        }
        if (length < 0)
        {
            throw new EOFException("EOF found when length expected");
        }
        if (0xFF == length)
        {
            throw new IOException("invalid long form definite-length 0xFF");
        }

        int octetsCount = length & 0x7F, octetsPos = 0;

        length = 0;
        do
        {
            int octet = s.read();
            if (octet < 0)
            {
                throw new EOFException("EOF found reading length");
            }

            if ((length >>> 23) != 0)
            {
                throw new IOException("long form definite-length more than 31 bits");
            }

            length = (length << 8) + octet;
        }
        while (++octetsPos < octetsCount);

        if (length >= limit)   // after all we must have read at least 1 byte
        {
            throw new IOException("corrupted stream - out of bounds length found: " + length + " >= " + limit);
        }

        return length;
    }

    final void writeTag(OutputStream out, int flags, int tag)
        throws IOException
    {
        if (tag < 31)
        {
            out.write(flags | tag);
        }
        else
        {
            byte[] stack = new byte[6];
            int pos = stack.length;

            stack[--pos] = (byte)(tag & 0x7F);
            while (tag > 127)
            {
                tag >>>= 7;
                stack[--pos] = (byte)(tag & 0x7F | 0x80);
            }

            stack[--pos] = (byte)(flags | 0x1F);

            out.write(stack, pos, stack.length - pos);
        }
    }

    final void writeLength(OutputStream out, int length)
        throws IOException
    {
        if (length < 128)
        {
            out.write(length);
        }
        else
        {
            byte[] stack = new byte[5];
            int pos = stack.length;

            do
            {
                stack[--pos] = (byte)length;
                length >>>= 8;
            }
            while (length != 0);

            int count = stack.length - pos;
            stack[--pos] = (byte)(0x80 | count);

            out.write(stack, pos, count + 1);
        }
    }

    private static void sort(List<byte[]> t)
    {
        int count = t.size();
        if (count < 2)
        {
            return;
        }

        byte[] bh = t.get(0), bi = t.get(1);

        if (lessThanOrEqual(bi, bh))
        {
            byte[] bt = bi;
            bi = bh;
            bh = bt;
        }

        for (int i = 2; i < count; ++i)
        {
            byte[] b2 = t.get(i);

            if (lessThanOrEqual(bi, b2))
            {
                t.set(i - 2, bh);
                bh = bi;
                bi = b2;
                continue;
            }

            if (lessThanOrEqual(bh, b2))
            {
                t.set(i - 2, bh);
                bh = b2;
                continue;
            }

            int j = i - 1;
            while (--j > 0)
            {
                byte[] b1 = t.get(j - 1);

                if (lessThanOrEqual(b1, b2))
                {
                    break;
                }

                t.set(j, b1);
            }

            t.set(j, b2);
        }

        t.set(count - 2, bh);
        t.set(count - 1, bi);
    }

    private static boolean lessThanOrEqual(byte[] a, byte[] b)
    {
        /*
         * NOTE: Set elements in DER encodings are ordered first according to their tags (class and
         * number); the CONSTRUCTED bit is not part of the tag.
         *
         * For SET-OF, this is unimportant. All elements have the same tag and DER requires them to
         * either all be in constructed form or all in primitive form, according to that tag. The
         * elements are effectively ordered according to their content octets.
         *
         * For SET, the elements will have distinct tags, and each will be in constructed or
         * primitive form accordingly. Failing to ignore the CONSTRUCTED bit could therefore lead to
         * ordering inversions.
         */
        int a0 = a[0] & (~BERTags.CONSTRUCTED & 0xff);
        int b0 = b[0] & (~BERTags.CONSTRUCTED & 0xff);
        if (a0 != b0)
        {
            return a0 < b0;
        }

        int last = Math.min(a.length, b.length) - 1;
        for (int i = 1; i < last; ++i)
        {
            if (a[i] != b[i])
            {
                return (a[i] & 0xFF) < (b[i] & 0xFF);
            }
        }
        return (a[last] & 0xFF) <= (b[last] & 0xFF);
    }

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
