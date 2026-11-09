package org.bouncycastle.ldap.test;

import junit.framework.TestCase;
import org.bouncycastle.ldap.LDAPUtils;

/**
 * Checks that values extracted from a DN by LDAPUtils are escaped (RFC 2254/4515)
 * before being placed in an LDAP search filter.
 */
public class LDAPUtilsTest
    extends TestCase
{
    public void testPlainValue()
    {
        assertEquals("Test User", LDAPUtils.parseDN("CN=Test User,O=Org,C=AU", "cn"));
        assertEquals("Test User", LDAPUtils.parseDN("CN=Test User", "CN"));
    }

    public void testFilterSpecialCharactersEscaped()
    {
        assertEquals("a\\2ab", LDAPUtils.parseDN("CN=a*b", "cn"));
        assertEquals("a\\28b", LDAPUtils.parseDN("CN=a(b", "cn"));
        assertEquals("a\\29b", LDAPUtils.parseDN("CN=a)b", "cn"));
        assertEquals("a\\5cb", LDAPUtils.parseDN("CN=a\\\\b", "cn"));
        assertEquals("a\\00b", LDAPUtils.parseDN("CN=a\0b", "cn"));
        assertEquals("\\2a", LDAPUtils.parseDN("CN=*", "cn"));
        assertEquals("chars[\\2a\\28\\29\\5c\\00]", LDAPUtils.parseDN("CN=chars[*()\\\\\0]", "cn"));
    }

    public void testFilterInjectionEscaped()
    {
        // a crafted RDN value which, unescaped, would close the substring assertion and
        // inject an additional filter component.
        assertEquals("x\\29\\28uid=admin", LDAPUtils.parseDN("CN=x)(uid=admin", "cn"));
        assertEquals("x\\29\\28uid=admin", LDAPUtils.parseDN("CN=\"x)(uid=admin\"", "cn"));
        assertEquals("\\2a\\29\\28|\\28objectClass=\\2a", LDAPUtils.parseDN("CN=*)(|(objectClass=*", "cn"));
        assertEquals("Org\\29\\28uid=\\2a", LDAPUtils.parseDN("CN=Test User, O=Org)(uid=*", "o"));
    }

    public void testEscapedCommaRetained()
    {
        assertEquals("a,b\\29\\28c", LDAPUtils.parseDN("CN=a\\,b)(c,O=Org", "cn"));
    }

    public void testMissingAttribute()
    {
        assertEquals("", LDAPUtils.parseDN("O=Org,C=AU", "cn"));
    }

    public void testAttributeNameInsideValueIgnored()
    {
        // "o=" inside another RDN's value must not be taken as the O attribute.
        assertEquals("Org", LDAPUtils.parseDN("CN=x\\, o=\\2a)(uid=\\2a, O=Org", "o"));
        assertEquals("Org", LDAPUtils.parseDN("CN=\"x, o=*)(uid=*\", O=Org", "o"));
    }

    public void testInvalidUTF8EscapesDecodedBytewise()
    {
        // truncated or malformed UTF-8 escapes must not throw, they are taken byte by byte
        assertEquals("bad\u00ff", LDAPUtils.parseDN("CN=bad\\FF, O=Org", "cn"));
        assertEquals("bad\u00c3", LDAPUtils.parseDN("CN=bad\\C3", "cn"));
        assertEquals("x\u00f0\u009f", LDAPUtils.parseDN("CN=x\\F0\\9F, O=Org", "cn"));
        assertEquals("\u00c0\u00aa", LDAPUtils.parseDN("CN=\\C0\\AA", "cn"));
        // a filter special character hidden inside a malformed sequence is still escaped
        assertEquals("\u00e2\\28\u00a1", LDAPUtils.parseDN("CN=\\E2\\28\\A1", "cn"));
        assertEquals("caf\u00e9\\2a", LDAPUtils.parseDN("CN=caf\\C3\\A9\\2A", "cn"));
    }
}
