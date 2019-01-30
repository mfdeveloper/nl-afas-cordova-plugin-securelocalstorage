package nl.afas.cordova.plugin.secureLocalStorage;

interface SecureLocalStorageListener {

    void onChange(SecureLocalStorage secureStorage, String key, Object value);
}
