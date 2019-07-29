package nl.afas.cordova.plugin.secureLocalStorage.lib.security.provider;

import java.security.Provider;

public class TestProvider extends Provider {

    /**
     * Constructs a provider with the specified name, version number,
     * and information.
     *
     * @param name    the provider name.
     * @param version the provider version number.
     * @param info    a description of the provider and its services.
     */
    public TestProvider(String name, double version, String info) {
        super(name, version, info);

        this.setProperty("KeyStore.AndroidKeyStore", "nl.afas.cordova.plugin.secureLocalStorage.lib.security.provider.TestKeyStoreSpi");
    }
}
