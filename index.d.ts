interface CordovaPlugins {
    SecureLocalStorage: SecureLocalStorage
}

interface SecureLocalStorage {
    getItem(key: string): Promise<any>;
    setItem(key: string, value: string): Promise<any>;
    removeItem(key: string): Promise<any>;
    clear(): Promise<any>;
}