package nl.afas.cordova.plugin.secureLocalStorage;

public enum KeyStoreType {
    CA_STORE("AndroidCAStore"),
    KEY_STORE("AndroidKeyStore"),
    DEFAULT;

    private String name = "";

    KeyStoreType() {

    }

    KeyStoreType(String s) {
        name = s;
    }

    public boolean equalsName(String otherName) {
        // (otherName == null) check is not needed because name.equals(null) returns false
        return name.equals(otherName);
    }

    public String toString() {
        return this.name;
    }
}
