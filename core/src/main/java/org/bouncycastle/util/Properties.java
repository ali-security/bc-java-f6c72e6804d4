package org.bouncycastle.util;

import java.math.BigInteger;
import java.security.AccessControlException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

/**
 * Utility method for accessing system properties.
 */
public class Properties
{
    private Properties()
    {

    }

    private static final ThreadLocal threadProperties = new ThreadLocal();

    /**
     * Opt in to handling legacy version 0/1 BKS keystores. Those stores derive the HMAC integrity
     * key at only the digest size in bits (a 16-bit key for SHA-1; CVE-2018-5382), which is
     * brute-forceable offline, so by default the default {@code BKS} keystore type refuses to load
     * them and only writes the current version 2 format. Set this property to read or create the
     * weak legacy format (e.g. to migrate an old store); it also gates registration of the separate
     * {@code BKS-V1} keystore type. Read via {@link #isOverrideSet(String)}.
     */
    public static final String BKS_ENABLE_V1 = "org.bouncycastle.bks.enable_v1";

    /**
     * Upper bound on the PBKDF2 iteration count honoured when BC takes that count from an
     * untrusted encoding: the raw JCA PBKDF2 provider (both the {@code SecretKeyFactory}
     * derivation - which is what decrypting a PBES2-protected PKCS#8 / PEM private key or PKCS#12
     * bag uses - and the {@code AlgorithmParameters} parse a {@code Cipher} performs for PBES2).
     * In each case the key-derivation parameters travel inside an unauthenticated container, so an
     * unbounded count makes processing attacker-supplied material a CPU-exhaustion vector. Default
     * 10,000,000 - the count RFC 8018 sec. 4.2 names as possibly appropriate for especially
     * critical keys, so generous enough for deliberately strong settings. Read via
     * {@link #asInteger(String, int)}.
     */
    public static final String PBE_MAX_ITERATION_COUNT = "org.bouncycastle.pbe.max_iteration_count";
                          
    /**
     * Return whether a particular override has been set to true.
     *
     * @param propertyName the property name for the override.
     * @return true if the property is set to "true", false otherwise.
     */
    public static boolean isOverrideSet(String propertyName)
    {
        try
        {
            String p = fetchProperty(propertyName);

            if (p != null)
            {
                return "true".equals(Strings.toLowerCase(p));
            }

            return false;
        }
        catch (AccessControlException e)
        {
            return false;
        }
    }

    /**
     * Enable the specified override property for the current thread only.
     *
     * @param propertyName the property name for the override.
     * @param enable true if the override should be enabled, false if it should be disabled.
     * @return true if the override was already set, false otherwise.
     */
    public static boolean setThreadOverride(String propertyName, boolean enable)
    {
        boolean isSet = isOverrideSet(propertyName);

        Map localProps = (Map)threadProperties.get();
        if (localProps == null)
        {
            localProps = new HashMap();
        }

        localProps.put(propertyName, enable ? "true" : "false");

        threadProperties.set(localProps);

        return isSet;
    }

    /**
     * Enable the specified override property in the current thread only.
     *
     * @param propertyName the property name for the override.
     * @return true if the override set true in thread local, false otherwise.
     */
    public static boolean removeThreadOverride(String propertyName)
    {
        boolean isSet = isOverrideSet(propertyName);

        Map localProps = (Map)threadProperties.get();
        if (localProps == null)
        {
            return false;
        }

        localProps.remove(propertyName);

        if (localProps.isEmpty())
        {
            threadProperties.remove();
        }
        else
        {
            threadProperties.set(localProps);
        }

        return isSet;
    }

    public static BigInteger asBigInteger(String propertyName)
    {
        String p = fetchProperty(propertyName);

        if (p != null)
        {
            return new BigInteger(p);
        }

        return null;
    }

    public static int asInteger(String propertyName, int defaultValue)
    {
        String p = fetchProperty(propertyName);

        if (p != null)
        {
            return Integer.parseInt(p);
        }

        return defaultValue;
    }

    public static Set<String> asKeySet(String propertyName)
    {
        Set<String> set = new HashSet<String>();

        String p = fetchProperty(propertyName);

        if (p != null)
        {
            StringTokenizer sTok = new StringTokenizer(p, ",");
            while (sTok.hasMoreElements())
            {
                set.add(Strings.toLowerCase(sTok.nextToken()).trim());
            }
        }

        return Collections.unmodifiableSet(set);
    }

    private static String fetchProperty(final String propertyName)
    {
        return (String)AccessController.doPrivileged(new PrivilegedAction()
        {
            public Object run()
            {
                Map localProps = (Map)threadProperties.get();
                if (localProps != null)
                {
                    return localProps.get(propertyName);
                }

                return System.getProperty(propertyName);
            }
        });
    }
}
