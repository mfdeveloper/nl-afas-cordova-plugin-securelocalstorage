package nl.afas.cordova.plugin.secureLocalStorage;

public interface SecureLocalStorageListener {

    void onChange(SecureLocalStorage secureStorage, String key, Object value);
}
