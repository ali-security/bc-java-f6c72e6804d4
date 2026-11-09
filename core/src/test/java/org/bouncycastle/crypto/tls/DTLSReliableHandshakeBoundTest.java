package org.bouncycastle.crypto.tls;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.SecureRandom;
import java.util.Hashtable;

import junit.framework.TestCase;

/**
 * CVE-2026-59646: the DTLS reassembler must not be sized from a declared handshake message
 * length above the maximum handshake message size.
 */
public class DTLSReliableHandshakeBoundTest
    extends TestCase
{
    private static final String MAX_SIZE_PROPERTY = "jdk.tls.maxHandshakeMessageSize";

    public void testOversizedDeclaredLengthIgnored()
        throws Exception
    {
        DTLSReliableHandshake handshake = createHandshake();

        processRecord(handshake, 0x100000);

        assertEquals("oversized ClientHello must not get a reassembler", 0, inboundFlightSize(handshake));
    }

    public void testDeclaredLengthWithinLimitAccepted()
        throws Exception
    {
        DTLSReliableHandshake handshake = createHandshake();

        processRecord(handshake, 32768);

        assertEquals(1, inboundFlightSize(handshake));
    }

    public void testLimitConfigurable()
        throws Exception
    {
        System.setProperty(MAX_SIZE_PROPERTY, String.valueOf(0x200000));
        DTLSReliableHandshake handshake;
        try
        {
            handshake = createHandshake();
        }
        finally
        {
            System.clearProperty(MAX_SIZE_PROPERTY);
        }

        processRecord(handshake, 0x100000);

        assertEquals(1, inboundFlightSize(handshake));
    }

    private static DTLSReliableHandshake createHandshake()
    {
        TlsContext context = new TlsServerContextImpl(new SecureRandom(), new SecurityParameters());
        return new DTLSReliableHandshake(context, null);
    }

    private static void processRecord(DTLSReliableHandshake handshake, int declaredLength)
        throws Exception
    {
        int fragmentLength = 16;
        byte[] record = new byte[12 + fragmentLength];
        TlsUtils.writeUint8(HandshakeType.client_hello, record, 0);
        TlsUtils.writeUint24(declaredLength, record, 1);
        TlsUtils.writeUint16(0, record, 4);
        TlsUtils.writeUint24(0, record, 6);
        TlsUtils.writeUint24(fragmentLength, record, 9);

        Method m = DTLSReliableHandshake.class.getDeclaredMethod("processRecord",
            new Class[]{ int.class, int.class, byte[].class, int.class, int.class });
        m.setAccessible(true);
        m.invoke(handshake, new Object[]{ Integer.valueOf(16), Integer.valueOf(0), record, Integer.valueOf(0),
            Integer.valueOf(record.length) });
    }

    private static int inboundFlightSize(DTLSReliableHandshake handshake)
        throws Exception
    {
        Field f = DTLSReliableHandshake.class.getDeclaredField("currentInboundFlight");
        f.setAccessible(true);
        return ((Hashtable)f.get(handshake)).size();
    }
}
