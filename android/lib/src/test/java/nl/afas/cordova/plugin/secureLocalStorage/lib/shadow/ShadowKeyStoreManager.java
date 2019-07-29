package nl.afas.cordova.plugin.secureLocalStorage.lib.shadow;

import org.robolectric.annotation.Implementation;
import org.robolectric.annotation.Implements;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;

import nl.afas.cordova.plugin.secureLocalStorage.KeyStoreManager;
import nl.afas.cordova.plugin.secureLocalStorage.KeyStoreType;
import nl.afas.cordova.plugin.secureLocalStorage.lib.security.provider.TestProvider;

@SuppressWarnings("WeakerAccess")
@Implements(KeyStoreManager.class)
public class ShadowKeyStoreManager {

    protected static Provider provider;
    protected static KeyStore keyStore;

    @Implementation
    @SuppressWarnings("unused")
    public static KeyStore getSystemKeyStore(KeyStoreType keyStoreType) throws
            KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {

        // @todo Search about custom Providers creation for Roboletric testing
        provider = new TestProvider("AndroidKeyStore", 1.0, "Fake AndroidKeyStore which is used for Robolectric tests");
        Security.addProvider(provider);

        keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(new FileInputStream(
                System.getProperty("java.home") + "/lib/security/cacerts"), null);
        return keyStore;
    }

    /**
     * @todo Search how can pass a custom provider with RSA algorithm
     *       for this method, called by Roboletric testing framework
     *
     * @return
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    @Implementation
    @SuppressWarnings("unused")
    public static KeyPairGenerator getKeyPairGenerator() throws
            NoSuchAlgorithmException, NoSuchProviderException {

        return KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");

    }
}
