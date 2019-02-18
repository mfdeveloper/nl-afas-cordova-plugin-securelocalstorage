package nl.afas.cordova.plugin.secureLocalStorage;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.widget.TextView;

public class MainActivity extends AppCompatActivity {

    private static class Person {
        protected String name;
        protected Integer age;

        public Person() {

        }

        public Person(String name, Integer age) {
            this.name = name;
            this.age = age;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public Integer getAge() {
            return age;
        }

        public void setAge(Integer age) {
            this.age = age;
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        try {
            this.initialize();
        }catch (SecureLocalStorage.SecureLocalStorageException err) {
            Log.e(err.getClass().getName(), err.getMessage(), err);
            err.printStackTrace();
        }
    }

    protected void initialize() throws SecureLocalStorage.SecureLocalStorageException {

        SecureLocalStorage localStorage = SecureLocalStorage.getInstance(this);

        localStorage.setItem("person", new Person("Morgan", 55));

        Person person = localStorage.getItem("person", Person.class);

        TextView textFirst = findViewById(R.id.textView);
        TextView textSecond = findViewById(R.id.textView2);
        textFirst.setText(String.format("Name from POJO: %s", person.getName()));
        textSecond.setText(String.format("JSON string: %s", localStorage.getItem("person")));
    }
}
