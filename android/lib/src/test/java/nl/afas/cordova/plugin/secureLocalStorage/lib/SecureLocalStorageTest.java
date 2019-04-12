package nl.afas.cordova.plugin.secureLocalStorage.lib;

import org.junit.Test;

import nl.afas.cordova.plugin.secureLocalStorage.SecureLocalStorage;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
public class SecureLocalStorageTest {

    protected static final SecureLocalStorage secureLocalStorage = SecureLocalStorage.getInstance();

    class PojoTest {

        protected String name;
        protected String value;

        public String getName() {
            return name;
        }

        public String getValue() {
            return value;
        }

        public void setName(String name) {
            this.name = name;
        }

        public void setValue(String value) {
            this.value = value;
        }
    }

    @Test
    public void itemClassObjectToJson() {
        PojoTest pojo = new PojoTest();
        pojo.setName("test");
        pojo.setValue("foo");

        try {
            boolean stored = secureLocalStorage.setItem("pojoObject", pojo);
            if (stored) {
                Object value = secureLocalStorage.getItem("pojoObject");
                assertNotNull(value);
                assertEquals(((PojoTest) value).getName(), "test");
            }

        } catch (SecureLocalStorage.SecureLocalStorageException e) {
            fail(e.getMessage());
            e.printStackTrace();
        }
    }
}