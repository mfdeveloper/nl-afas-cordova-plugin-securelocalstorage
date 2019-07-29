package nl.afas.cordova.plugin.secureLocalStorage;

import java.io.IOException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

public class KeyStoreManager {

    public static KeyStore getSystemKeyStore(KeyStoreType keyStoreType) throws
        KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {

        String type = keyStoreType.toString();

        if (keyStoreType.equals(KeyStoreType.DEFAULT)) {
            type = KeyStore.getDefaultType();
        }

        KeyStore keyStore = KeyStore.getInstance(type);
        keyStore.load(null, null);
        return keyStore;
    }

    /**
     * @todo Search how can pass a custom provider for
     *       shadoweb class with this same method name,
     *       for Roboletric testing. By now, got exception:
     *       "java.security.NoSuchAlgorithmException: no such algorithm: RSA for provider AndroidKeyStore"
     *
     * @return
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static KeyPairGenerator getKeyPairGenerator() throws
            NoSuchAlgorithmException, NoSuchProviderException {

        return KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
    }
}
