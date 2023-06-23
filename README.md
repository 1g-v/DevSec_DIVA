# DevSec_DIVA
## Поиск уязвимостей и ошибок конфигурации в мобильном приложении DIVA на базе операционной системы Android
### AccessControl1Activity
```java
package jakhar.aseem.diva;

import android.content.Intent;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Toast;

public class AccessControl1Activity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_access_control1);
    }

    public void viewAPICredentials(View view) {
        // Calling implicit intent i.e. with app defined action instead of activity class
        Intent i = new Intent();
        i.setAction("jakhar.aseem.diva.action.VIEW_CREDS");
        // Check whether the intent resolves to an activity or not
        if (i.resolveActivity(getPackageManager()) != null){
            startActivity(i);
        }
        else {
            Toast.makeText(this, "Error while getting API details", Toast.LENGTH_SHORT).show();
            Log.e("Diva-aci1", "Couldn't resolve the Intent VIEW_CREDS to our activity");
        }
    }
}
```
| Идентификатор | Описание | Исправление/смягчение |
|----|----|----|
| CWE-926: Improper Export of Android Application Components | Реализовано намерение (Intent) с использованием неявного вызова, что может привести к тому, что другие потенциально вредоносные приложения на устройстве смогут перехватывать и использовать это намерение | Использование явного намерения, указав имя пакета и класса, которые должны обрабатывать это намерение |
| CWE-532: Insertion of Sensitive Information into Log File | Включен журнал ошибок (Log.e), который может быть доступен другим приложениям на устройстве и злоумышленникам. Это может стать причиной утечки данных или их компрометации | Исключение или замена журнала ошибок на другой метод, который более безопасен. Предпочтительно использовать protected logger, либо не использовать журнал вовсе |

### AccessControl2Activity
```java
package jakhar.aseem.diva;

import android.content.Intent;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.RadioButton;
import android.widget.Toast;

public class AccessControl2Activity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_access_control2);
    }

    public void viewAPICredentials(View view) {
        //RadioButton rbalreadyreg = (RadioButton) findViewById(R.id.aci2rbalreadyreg);
        RadioButton rbregnow = (RadioButton) findViewById(R.id.aci2rbregnow);
        Intent i = new Intent();
        boolean chk_pin = rbregnow.isChecked();

        // Calling implicit intent i.e. with app defined action instead of activity class
        i.setAction("jakhar.aseem.diva.action.VIEW_CREDS2");
        i.putExtra(getString(R.string.chk_pin), chk_pin);
        // Check whether the intent resolves to an activity or not
        if (i.resolveActivity(getPackageManager()) != null){
            startActivity(i);
        }
        else {
            Toast.makeText(this, "Error while getting Tveeter API details", Toast.LENGTH_SHORT).show();
            Log.e("Diva-aci1", "Couldn't resolve the Intent VIEW_CREDS2 to our activity");
        }
    }
}
```
| Идентификатор | Описание | Исправление/смягчение |
|----|----|----|
| CWE-926: Использование небезопасных функций Intent | Реализовано намерение `Intent` с использованием неявного вызова, что может привести к тому, что другие потенциально вредоносные приложения на устройстве смогут перехватывать и использовать это намерение | Использование явного намерения, указав имя пакета и класса, которые должны обрабатывать это намерение |
| CWE-669: Incorrect Resource Permissions | Вызов `rbregnow.isChecked()` без проверки, выбран ли предыдущий элемент RadioButton или нет. Это может привести к некорректной работе приложения, если пользователь нажал другую радио-кнопку. | Добавление проверки, задействована ли предыдущая радио-кнопка или нет, и действовать соответственно результатам проверки. |

### AccessControl3Activity
```java
package jakhar.aseem.diva;

import android.content.Intent;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

public class AccessControl3Activity extends AppCompatActivity {


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_access_control3);

        SharedPreferences spref = PreferenceManager.getDefaultSharedPreferences(this);
        String pin = spref.getString(getString(R.string.pkey), "");

        if (!pin.isEmpty()) {
            Button vbutton = (Button) findViewById(R.id.aci3viewbutton);
            vbutton.setVisibility(View.VISIBLE);
        }
    }

    public void addPin(View view) {
        SharedPreferences spref = PreferenceManager.getDefaultSharedPreferences(this);
        SharedPreferences.Editor spedit = spref.edit();
        EditText pinTxt = (EditText) findViewById(R.id.aci3Pin);
        String pin = pinTxt.getText().toString();

        if (pin == null || pin.isEmpty()) {
            Toast.makeText(this, "Please Enter a valid pin!", Toast.LENGTH_SHORT).show();
        }
        else {
            Button vbutton = (Button) findViewById(R.id.aci3viewbutton);
            spedit.putString(getString(R.string.pkey), pin);
            spedit.commit();
            if (vbutton.getVisibility() != View.VISIBLE) {
                vbutton.setVisibility(View.VISIBLE);
            }

            Toast.makeText(this, "PIN Created successfully. Private notes are now protected with PIN", Toast.LENGTH_SHORT).show();
        }
    }

    public void goToNotes(View view) {
        Intent i = new Intent(this, AccessControl3NotesActivity.class);
        startActivity(i);
    }
}
```
| Идентификатор | Описание | Исправление/смягчение |
|----|----|----|
| CWE-312: Cleartext Storage of Sensitive Information | PIN-код сохраняется в `Shared Preferences`, которые хранятся в незашифрованном виде. Обработка чувствительных данных, таких как пароли или пин-коды, без использования шифрования может привести к компрометации данных пользователей | Использование надежной криптографической функции шифрования для хранения чувствительных данных в зашифрованном виде |
| CWE-20: Improper Input Validation | Проверка получаемой от пользователя значение переменной `pin` только на то, что она не пустая | Необходима более строгая валидация и проверка получаемых от пользователя данных |
| CWE-919: Weak Password Requirements | Реализованная проверка на валидность пароля недостаточно строга | Реализовать более сильные требования к паролю, которые будут соответствовать политикам безопасности |
| CWE-319: Cleartext Transmission of Sensitive Data | Нет явного указания, должна ли передача данных выполняться в зашифрованном виде. Обработка чувствительных данных, таких как пароли или пин-коды, без использования протоколов транспортного уровня сессии (например, TLS) или другой технологии шифрования может привести к компрометации данных пользователей | Использование TLS для передачи данных |

### AccessControl3NotesActivity
```java
package jakhar.aseem.diva;

import android.content.ContentResolver;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.preference.PreferenceManager;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.SimpleCursorAdapter;
import android.widget.TextView;
import android.widget.Toast;

public class AccessControl3NotesActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_access_control3_notes);
    }

    public void accessNotes(View view) {
        EditText pinTxt = (EditText) findViewById(R.id.aci3notesPinText);
        Button abutton = (Button) findViewById(R.id.aci3naccessbutton);
        SharedPreferences spref = PreferenceManager.getDefaultSharedPreferences(this);
        String pin = spref.getString(getString(R.string.pkey), "");
        String userpin = pinTxt.getText().toString();

        // XXX Easter Egg?
        if (userpin.equals(pin)) {
            // Display the private notes
            ListView  lview = (ListView) findViewById(R.id.aci3nlistView);
            Cursor cr = getContentResolver().query(NotesProvider.CONTENT_URI, new String[] {"_id", "title", "note"}, null, null, null);
            String[] columns = {NotesProvider.C_TITLE, NotesProvider.C_NOTE};
            int [] fields = {R.id.title_entry, R.id.note_entry};
            SimpleCursorAdapter adapter = new SimpleCursorAdapter(this, R.layout.notes_entry ,cr, columns, fields, 0);
            lview.setAdapter(adapter);
            pinTxt.setVisibility(View.INVISIBLE);
            abutton.setVisibility(View.INVISIBLE);
            //cr.close();

        }
        else {
            Toast.makeText(this, "Please Enter a valid pin!", Toast.LENGTH_SHORT).show();
        }

    }
}
```
| Идентификатор | Описание | Исправление/смягчение |
|----|----|----|
| CWE-259: Use of Hard-coded Password | Хранение пароля реализовано в коде приложения в незашифрованном виде и не является безопасным | Использование надежной криптографической функции шифрования для хранения чувствительных данных в зашифрованном виде |
| CWE-311: Missing Encryption of Sensitive Data | Записи заметок не зашифрованы, что может привести к утечкам конфиденциальной информации | Использование надежной криптографической функции шифрования для хранения чувствительных данных в зашифрованном виде |
| CWE-295: Improper Certificate Validation | В исследуемом коде отсутствует проверка подлинности сервера при получении данных из удаленного источника | Использование проверки сертификата подлинности, для защиты взаимодействия с внешним сервером |
| CWE-602: Client-Side Enforcement of Server-Side Security | Клиентское приложение не полностью доверяет серверу при проверке авторизации | Проверка авторизации на стороне сервера |
