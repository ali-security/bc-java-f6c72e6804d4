package org.bouncycastle.asn1.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;


/**
 * X.690 test example
 */
public class OIDTest
    extends SimpleTest
{
    byte[]    req1 = Hex.decode("0603813403");
    byte[]    req2 = Hex.decode("06082A36FFFFFFDD6311");

    public String getName()
    {
        return "OID";
    }
    
    private void recodeCheck(
        String oid, 
        byte[] enc) 
        throws IOException
    {
        ByteArrayInputStream     bIn = new ByteArrayInputStream(enc);
        ASN1InputStream          aIn = new ASN1InputStream(bIn);

        ASN1ObjectIdentifier      o = new ASN1ObjectIdentifier(oid);
        ASN1ObjectIdentifier      encO = (ASN1ObjectIdentifier)aIn.readObject();
        
        if (!o.equals(encO))
        {
            fail("oid ID didn't match", o, encO);
        }
        
        ByteArrayOutputStream    bOut = new ByteArrayOutputStream();
        DEROutputStream          dOut = new DEROutputStream(bOut);

        dOut.writeObject(o);

        byte[]                    bytes = bOut.toByteArray();

        if (bytes.length != enc.length)
        {
            fail("failed length test");
        }

        for (int i = 0; i != enc.length; i++)
        {
            if (bytes[i] != enc[i])
            {
                fail("failed comparison test", new String(Hex.encode(enc)), new String(Hex.encode(bytes)));
            }
        }
    }
    
    private void validOidCheck(
        String  oid)
        throws IOException
    {
        ASN1ObjectIdentifier     o = new ASN1ObjectIdentifier(oid);
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
        ASN1OutputStream        aOut = new ASN1OutputStream(bOut);
        
        aOut.writeObject(o);
        
        ByteArrayInputStream    bIn = new ByteArrayInputStream(bOut.toByteArray());
        ASN1InputStream         aIn = new ASN1InputStream(bIn);
        
        o = (ASN1ObjectIdentifier)aIn.readObject();
        
        if (!o.getId().equals(oid))
        {
            fail("failed oid check for " + oid);
        }
    }

    private void invalidOidCheck(
        String oid)
    {
        try
        {
            new ASN1ObjectIdentifier(oid);
            fail("failed to catch bad oid: " + oid);
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void branchCheck(String stem, String branch)
    {
        String expected = stem + "." + branch;
        String actual = new ASN1ObjectIdentifier(stem).branch(branch).getId();

        if (!expected.equals(actual))
        {
            fail("failed 'branch' check for " + stem + "/" + branch);
        }
    }

    private void onCheck(String stem, String test, boolean expected)
    {
        if (expected != new ASN1ObjectIdentifier(test).on(new ASN1ObjectIdentifier(stem)))
        {
            fail("failed 'on' check for " + stem + "/" + test);
        }
    }

    private static byte[] encodeOid(int contentsLength)
    {
        // 06 82 LL LL followed by contentsLength single-octet subidentifiers
        byte[] enc = new byte[4 + contentsLength];
        enc[0] = 0x06;
        enc[1] = (byte)0x82;
        enc[2] = (byte)(contentsLength >> 8);
        enc[3] = (byte)contentsLength;
        for (int i = 4; i < enc.length; i++)
        {
            enc[i] = 0x01;
        }
        return enc;
    }

    private static String repeatedOid(String stem, int count)
    {
        StringBuffer sb = new StringBuffer(stem);
        for (int i = 0; i < count; i++)
        {
            sb.append(".1");
        }
        return sb.toString();
    }

    private void contentsLengthLimitCheck()
        throws IOException
    {
        // CVE-2025-8885: OID contents are limited to 4096 octets
        ASN1ObjectIdentifier maxOid = (ASN1ObjectIdentifier)new ASN1InputStream(encodeOid(4096)).readObject();
        isTrue("4096 octet OID not parsed", maxOid.getEncoded().length == 4 + 4096);

        try
        {
            new ASN1InputStream(encodeOid(4097)).readObject();
            fail("no exception on 4097 octet OID");
        }
        catch (IOException e)
        {
            isTrue("unexpected cause: " + e.getCause(), e.getCause() instanceof IllegalArgumentException
                && "exceeded OID contents length limit".equals(e.getCause().getMessage()));
        }

        try
        {
            ASN1ObjectIdentifier.getInstance(encodeOid(4097));
            fail("no exception on 4097 octet OID via getInstance");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }

        try
        {
            new ASN1StreamParser(encodeOid(4097)).readObject();
            fail("no exception on 4097 octet OID via stream parser");
        }
        catch (IOException e)
        {
            isTrue("unexpected cause: " + e.getCause(), e.getCause() instanceof IllegalArgumentException
                && "exceeded OID contents length limit".equals(e.getCause().getMessage()));
        }

        byte[] longContents = new byte[4097];
        for (int i = 0; i < longContents.length; i++)
        {
            longContents[i] = 0x01;
        }
        try
        {
            ASN1ObjectIdentifier.getInstance(new DERTaggedObject(false, 0, new DEROctetString(longContents)), false);
            fail("no exception on 4097 octet implicitly tagged OID");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("exceeded OID contents length limit", e.getMessage());
        }

        // "0.1" encodes as a single octet, every further ".1" adds one octet
        isTrue(new ASN1ObjectIdentifier(repeatedOid("0.1", 4095)).getEncoded().length == 4 + 4096);
        try
        {
            new ASN1ObjectIdentifier(repeatedOid("0.1", 4096));
            fail("no exception on 4097 octet OID string");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("exceeded OID contents length limit", e.getMessage());
        }

        StringBuffer longArc = new StringBuffer("1.2.");
        for (int i = 0; i < 4 * 4096; i++)
        {
            longArc.append('9');
        }
        try
        {
            new ASN1ObjectIdentifier(longArc.toString());
            fail("no exception on over-long OID string");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("exceeded OID contents length limit", e.getMessage());
        }

        ASN1ObjectIdentifier stem = new ASN1ObjectIdentifier(repeatedOid("0.1", 4094));
        isTrue(stem.branch("1").getEncoded().length == 4 + 4096);
        try
        {
            stem.branch("1.1");
            fail("no exception on 4097 octet OID branch");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("exceeded OID contents length limit", e.getMessage());
        }
    }

    public void performTest()
        throws IOException
    {
        recodeCheck("2.100.3", req1);
        recodeCheck("1.2.54.34359733987.17", req2);
        
        validOidCheck(PKCSObjectIdentifiers.pkcs_9_at_contentType.getId());
        validOidCheck("0.1");
        validOidCheck("1.1.127.32512.8323072.2130706432.545460846592.139637976727552.35747322042253312.9151314442816847872");
        validOidCheck("1.2.123.12345678901.1.1.1");
        validOidCheck("2.25.196556539987194312349856245628873852187.1");

        invalidOidCheck("0");
        invalidOidCheck("1");
        invalidOidCheck("2");
        invalidOidCheck("3.1");
        invalidOidCheck("..1");
        invalidOidCheck("192.168.1.1");
        invalidOidCheck(".123452");
        invalidOidCheck("1.");
        invalidOidCheck("1.345.23.34..234");
        invalidOidCheck("1.345.23.34.234.");
        invalidOidCheck(".12.345.77.234");
        invalidOidCheck(".12.345.77.234.");
        invalidOidCheck("1.2.3.4.A.5");
        invalidOidCheck("1,2");

        branchCheck("1.1", "2.2");

        onCheck("1.1", "1.1", false);
        onCheck("1.1", "1.2", false);
        onCheck("1.1", "1.2.1", false);
        onCheck("1.1", "2.1", false);
        onCheck("1.1", "1.11", false);
        onCheck("1.12", "1.1.2", false);
        onCheck("1.1", "1.1.1", true);
        onCheck("1.1", "1.1.2", true);

        contentsLengthLimitCheck();
    }

    public static void main(
        String[]    args)
    {
        runTest(new OIDTest());
    }
}
