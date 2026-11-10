package org.bouncycastle.pkix.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathValidator;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import junit.framework.TestCase;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkix.jcajce.PKIXCertPathReviewer;
import org.bouncycastle.pkix.util.ErrorBundle;

/**
 * Name constraint checking in the {@link PKIXCertPathReviewer} against a malicious chain
 * (root, ca1, ca2, leaf) in which ca1 carries a large set of name constraints and ca2/leaf
 * carry a large subject alternative name extension. Without a limit on the number of subject
 * alternative names the reviewer performs (alt names x name constraints) checks, which can be
 * used to exhaust resources.
 */
public class CheckNameConstraintsTest
    extends TestCase
{
    private static final String SUBJ_ALT_NAME_EXT_ERROR = "CertPathReviewer.subjAltNameExtError";
    private static final String NOT_PERMITTED_EMAIL = "CertPathReviewer.notPermittedEmail";

    private static final int NAME_CHECK_MAX = 1024;

    private static final int MALICIOUS_PERMITTED_COUNT = 1500;
    private static final int MALICIOUS_EXCLUDED_COUNT = 500;
    private static final int MALICIOUS_ALT_NAME_COUNT = 1500;

    private static final X500Name ROOT_NAME = new X500Name("CN=Name Constraints Test Root");
    private static final X500Name CA1_NAME = new X500Name("CN=Name Constraints Test CA1");
    private static final X500Name CA2_NAME = new X500Name("CN=Name Constraints Test CA2");
    private static final X500Name LEAF_NAME = new X500Name("CN=Name Constraints Test Leaf");

    private static BigInteger serialNumber = BigInteger.ONE;

    private static KeyPair rootKp;
    private static KeyPair ca1Kp;
    private static KeyPair ca2Kp;
    private static KeyPair leafKp;

    private static X509Certificate rootCert;
    private static X509Certificate ca1Cert;

    protected void setUp()
        throws Exception
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        if (rootKp == null)
        {
            rootKp = generateKeyPair();
            ca1Kp = generateKeyPair();
            ca2Kp = generateKeyPair();
            leafKp = generateKeyPair();

            rootCert = makeCertificate(ROOT_NAME, rootKp.getPrivate(), ROOT_NAME, rootKp.getPublic(),
                true, null, null);
            ca1Cert = makeCertificate(ROOT_NAME, rootKp.getPrivate(), CA1_NAME, ca1Kp.getPublic(),
                true, null, createMaliciousNameConstraints());
        }
    }

    /**
     * Review the malicious chain: ca2 carries more subject alternative names than the reviewer
     * is prepared to check against ca1's name constraints, so it must be rejected with a
     * subject alternative name error rather than being checked name by name.
     */
    public void testPKIXCertPathReviewer()
        throws Exception
    {
        PKIXCertPathReviewer certPathReviewer = reviewMaliciousPath(createAltNames(MALICIOUS_ALT_NAME_COUNT, null));

        assertFalse("malicious path must not be valid", certPathReviewer.isValidCertPath()); // hit
        assertTrue("malicious subject alternative names must be rejected, errors: " + errorIds(certPathReviewer),
            hasError(certPathReviewer, 1, SUBJ_ALT_NAME_EXT_ERROR));
        assertFalse("malicious subject alternative names must not be checked one by one, errors: "
            + errorIds(certPathReviewer), hasError(certPathReviewer, 1, NOT_PERMITTED_EMAIL));
    }

    public void testPKIXCertPathBuilder()
        throws Exception
    {
        X509Certificate endCert = ca1Cert;

        // create CertStore to support path building
        List list = new ArrayList();
        list.add(endCert);

        CollectionCertStoreParameters params = new CollectionCertStoreParameters(list);
        CertStore                     store = CertStore.getInstance("Collection", params, "BC");

        // build the path
        CertPathBuilder  builder = CertPathBuilder.getInstance("PKIX", "BC");
        X509CertSelector pathConstraints = new X509CertSelector();

        pathConstraints.setCertificate(endCert);

        PKIXBuilderParameters buildParams = new PKIXBuilderParameters(Collections.singleton(new TrustAnchor(rootCert, null)), pathConstraints);

        buildParams.addCertStore(store);
        buildParams.setDate(new Date());
        buildParams.setRevocationEnabled(false);

        PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult)builder.build(buildParams);
        CertPath                  path = result.getCertPath();

        if (path.getCertificates().size() != 1)
        {
            fail("wrong number of certs in testPKIXCertPathBuilder path");
        }
    }

    public void testPKIXCertPathValidator()
        throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        X509Certificate endCert = ca1Cert;

        List list = new ArrayList();
        list.add(endCert);

        CertPath certPath = cf.generateCertPath(list);

        Set trust = new HashSet();
        trust.add(new TrustAnchor(rootCert, null));

        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", "BC");
        PKIXParameters param = new PKIXParameters(trust);
        param.setRevocationEnabled(false);

        cpv.validate(certPath, param);
    }

    /**
     * A CA certificate carrying exactly the maximum number of subject alternative names
     * must still be checked normally against the name constraints.
     */
    public void testPKIXCertPathReviewerSubjAltNamesAtLimit()
        throws Exception
    {
        PKIXCertPathReviewer certPathReviewer = reviewMaliciousPath(createAltNames(NAME_CHECK_MAX, null));

        assertFalse("subject alternative names at the limit must not be rejected, errors: " + errorIds(certPathReviewer),
            hasError(certPathReviewer, 1, SUBJ_ALT_NAME_EXT_ERROR));
        assertTrue("path should be valid, errors: " + errorIds(certPathReviewer),
            certPathReviewer.isValidCertPath());
    }

    /**
     * A CA certificate carrying one more subject alternative name than the maximum must be
     * rejected before the names are checked against the name constraints.
     */
    public void testPKIXCertPathReviewerSubjAltNamesOverLimit()
        throws Exception
    {
        PKIXCertPathReviewer certPathReviewer = reviewMaliciousPath(createAltNames(NAME_CHECK_MAX + 1, null));

        assertFalse("path with subject alternative names over the limit must not be valid",
            certPathReviewer.isValidCertPath());
        assertTrue("subject alternative names over the limit must be rejected, errors: " + errorIds(certPathReviewer),
            hasError(certPathReviewer, 1, SUBJ_ALT_NAME_EXT_ERROR));
    }

    /**
     * Within the limit the subject alternative names are still checked one by one, so a single
     * name outside of the permitted subtrees must be reported.
     */
    public void testPKIXCertPathReviewerNotPermittedAltNameWithinLimit()
        throws Exception
    {
        PKIXCertPathReviewer certPathReviewer = reviewMaliciousPath(
            createAltNames(16, new GeneralName(GeneralName.dNSName, "host.not-permitted.example")));

        assertFalse("path with a not permitted subject alternative name must not be valid",
            certPathReviewer.isValidCertPath());
        assertTrue("not permitted subject alternative name must be reported, errors: " + errorIds(certPathReviewer),
            hasError(certPathReviewer, 1, NOT_PERMITTED_EMAIL));
        assertFalse("subject alternative names within the limit must not be rejected as a whole, errors: "
            + errorIds(certPathReviewer), hasError(certPathReviewer, 1, SUBJ_ALT_NAME_EXT_ERROR));
    }

    private static PKIXCertPathReviewer reviewMaliciousPath(GeneralNames ca2AltNames)
        throws Exception
    {
        X509Certificate ca2Cert = makeCertificate(CA1_NAME, ca1Kp.getPrivate(), CA2_NAME, ca2Kp.getPublic(),
            true, ca2AltNames, null);
        X509Certificate leafCert = makeCertificate(CA2_NAME, ca2Kp.getPrivate(), LEAF_NAME, leafKp.getPublic(),
            false, createAltNames(MALICIOUS_ALT_NAME_COUNT, null), null);

        List certchain = new ArrayList();
        certchain.add(leafCert);
        certchain.add(ca2Cert);
        certchain.add(ca1Cert);

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        CertPath cp = cf.generateCertPath(certchain);

        Set trust = new HashSet();
        trust.add(new TrustAnchor(rootCert, null));
        PKIXParameters param = new PKIXParameters(trust);
        param.setRevocationEnabled(false);

        PKIXCertPathReviewer certPathReviewer = new PKIXCertPathReviewer();
        certPathReviewer.init(cp, param);

        return certPathReviewer;
    }

    /**
     * Name constraints with many permitted and excluded subtrees, the permitted ones covering
     * every subject alternative name produced by {@link #createAltNames(int, GeneralName)}.
     */
    private static NameConstraints createMaliciousNameConstraints()
    {
        GeneralSubtree[] permitted = new GeneralSubtree[MALICIOUS_PERMITTED_COUNT];
        for (int i = 0; i != permitted.length; i++)
        {
            permitted[i] = new GeneralSubtree(new GeneralName(GeneralName.dNSName, "permitted" + i + ".example.com"));
        }

        GeneralSubtree[] excluded = new GeneralSubtree[MALICIOUS_EXCLUDED_COUNT];
        for (int i = 0; i != excluded.length; i++)
        {
            excluded[i] = new GeneralSubtree(new GeneralName(GeneralName.dNSName, "excluded" + i + ".example.com"));
        }

        return new NameConstraints(permitted, excluded);
    }

    private static GeneralNames createAltNames(int count, GeneralName extraName)
    {
        GeneralName[] altNames = new GeneralName[(extraName == null) ? count : count + 1];
        for (int i = 0; i != count; i++)
        {
            altNames[i] = new GeneralName(GeneralName.dNSName,
                "host" + i + ".permitted" + (i % MALICIOUS_PERMITTED_COUNT) + ".example.com");
        }
        if (extraName != null)
        {
            altNames[count] = extraName;
        }
        return new GeneralNames(altNames);
    }

    private static KeyPair generateKeyPair()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
        kpGen.initialize(1024);

        return kpGen.generateKeyPair();
    }

    private static X509Certificate makeCertificate(X500Name issuer, PrivateKey issuerKey, X500Name subject,
        PublicKey subjectKey, boolean isCa, GeneralNames subjectAltNames, NameConstraints nameConstraints)
        throws Exception
    {
        long now = System.currentTimeMillis();

        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
            issuer,
            allocateSerialNumber(),
            new Date(now - (1000L * 60 * 60)),
            new Date(now + (1000L * 60 * 60 * 24)),
            subject,
            subjectKey);

        if (isCa)
        {
            certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            certGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        }
        else
        {
            certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            certGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        }

        if (subjectAltNames != null)
        {
            certGen.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);
        }

        if (nameConstraints != null)
        {
            certGen.addExtension(Extension.nameConstraints, true, nameConstraints);
        }

        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC");

        return new JcaX509CertificateConverter().setProvider("BC")
            .getCertificate(certGen.build(contentSignerBuilder.build(issuerKey)));
    }

    private static synchronized BigInteger allocateSerialNumber()
    {
        BigInteger serial = serialNumber;
        serialNumber = serialNumber.add(BigInteger.ONE);
        return serial;
    }

    private static boolean hasError(PKIXCertPathReviewer certPathReviewer, int index, String id)
    {
        for (Iterator it = certPathReviewer.getErrors(index).iterator(); it.hasNext();)
        {
            ErrorBundle msg = (ErrorBundle)it.next();
            if (id.equals(msg.getId()))
            {
                return true;
            }
        }
        return false;
    }

    private static String errorIds(PKIXCertPathReviewer certPathReviewer)
    {
        StringBuffer sb = new StringBuffer();
        List[] errors = certPathReviewer.getErrors();
        for (int i = 0; i != errors.length; i++)
        {
            for (Iterator it = errors[i].iterator(); it.hasNext();)
            {
                ErrorBundle msg = (ErrorBundle)it.next();
                sb.append('[').append(i - 1).append("] ").append(msg.getId()).append(' ');
            }
        }
        return sb.toString();
    }
}
