package nl.afas.cordova.plugin.secureLocalStorage.lib.security.provider;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Enumeration;

public class TestKeyStoreSpi extends KeyStoreSpi {

    protected KeyStore wrapped;

    public TestKeyStoreSpi() throws KeyStoreException {
        super();
        wrapped = KeyStore.getInstance(KeyStore.getDefaultType());
    }


    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        try {
            return wrapped.getKey(alias, password);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        try {
            return wrapped.getCertificateChain(alias);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        try {
            return wrapped.getCertificate(alias);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Date engineGetCreationDate(String alias) {
        try {
            return wrapped.getCreationDate(alias);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
        wrapped.setKeyEntry(alias, key, password, chain);
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
        wrapped.setKeyEntry(alias, key, chain);
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
        wrapped.setCertificateEntry(alias, cert);
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException {
        wrapped.deleteEntry(alias);
    }

    @Override
    public Enumeration<String> engineAliases() {
        try {
            return wrapped.aliases();
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        try {
            return wrapped.containsAlias(alias);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public int engineSize() {
        try {
            return wrapped.size();
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        try {
            return wrapped.isKeyEntry(alias);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        try {
            return wrapped.isCertificateEntry(alias);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        try {
            return wrapped.getCertificateAlias(cert);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void engineStore(OutputStream stream, char[] password) throws CertificateException, IOException, NoSuchAlgorithmException {
        try {
            wrapped.store(stream, password);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void engineLoad(InputStream stream, char[] password) throws CertificateException, IOException, NoSuchAlgorithmException {
        wrapped.load(stream, password);
    }
}
