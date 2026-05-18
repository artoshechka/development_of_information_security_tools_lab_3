# Лабораторная работа по предмету: "Разработка средств защиты информации"
## Тема: "Dll инъекции в С++ код и противодействие инъекции"
> 4 курс 2 семестр \
> Студент группы 932223 - **Артеменко Антон Дмитриевич** 

## 1. Постановка задачи
### Ознакомиться с механизмом инъекции на примере пользовательского проекта.
Проект: https://disk.yandex.ru/d/xgNGbBK37pmMgQ
Механизм: https://disk.yandex.ru/i/LhhjTMd3mLKS6w

### Реализовать защиту от инъекции.
Защита(1 вариант): https://disk.yandex.ru/i/oj5Lm1NgeCDiZQ

Реализованный метод: `UpdateProcThreadAttribute`

---

## 2. Принцип работы

```
Инжектор                                 Целевой процесс
──────────────────────────────────────────────────────────
1. OpenProcess(PID)          ──────────► получаем дескриптор с правами на VM и потоки
2. VirtualAllocEx(hProcess)  ──────────► выделяем страницу памяти в куче жертвы
3. WriteProcessMemory(...)   ──────────► пишем туда путь "VirusDLL.dll\0"
4. CreateRemoteThread(
       LoadLibraryA,
       <адрес строки>)       ──────────► Windows сама вызывает LoadLibraryA(...)
                                         → срабатывает DllMain(DLL_PROCESS_ATTACH)
                                         → Attack() показывает MessageBox
```

После четвёртого шага DLL живёт внутри чужого процесса и выполняется в его контексте — с его правами, памятью и доступом к его данным.

`OpenProcess` требует флаги `PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION`, то есть инжектор должен быть запущен от того же пользователя, что и жертва, либо от администратора.

---

## 3. Структура проекта

```
├── CMakeLists.txt             — сборочный скрипт
│
├── VirusDLL/                  — сама внедряемая DLL
│   └── Source.cpp
│
├── DLLInjectorAsProcess/      — инжектор в виде .exe
│   └── Source.cpp
│
├── DllInjectorAsDll/          — инжектор в виде .dll (запускается через Rundll32)
│   ├── Source.cpp
│   └── DllInjectorAsDll.def
│
├── TargetProcess/             — процесс-жертва, бесконечно считает секунды
│   └── Source.cpp
│
├── DLLLoader/                 — простая проверка, что VirusDLL вообще работает
│   └── Source.cpp
│
├── ProtectedProcess/          — процесс-жертва с защитой от загрузки сторонних DLL
│   └── Source.cpp
│
└── Prize.html                 — фишинговая страница для демонстрации через IE
```

---

## 4. Что делает каждый модуль

### VirusDLL

Внедряемое ПО. Как только DLL загружается в чужой процесс, срабатывает `DllMain` с событием `DLL_PROCESS_ATTACH`, который вызывает `Attack()`. Та спрашивает у Windows имя текущего процесса через `GetModuleBaseNameA` и показывает `MessageBox` с этим именем в заголовке — наглядное доказательство, что DLL оказалась там, где нужно.

### TargetProcess

Бесконечный цикл, который раз в секунду печатает счётчик. Также выводит PID, который будет передаваться инжектору

### DLLInjectorAsProcess

Консольная программа, которая принимает PID жертвы первым аргументом и выполняет все четыре шага инъекции.

```
DLLInjectorAsProcess.exe <PID>
```

`VirusDLL.dll` должна лежать рядом или быть доступна через переменные среды.

### DllInjectorAsDll

Та же логика инъекции, упакованная в DLL. Запускается через `Rundll32.exe` — системную утилиту Windows — без отдельного исполняемого файла. Экспортирует функцию `HelperFunc`, которой Rundll32 передаёт PID жертвы строкой:

```
Rundll32.exe <path>/DllInjectorAsDll.dll HelperFunc <PID>
```

### DLLLoader

Вызывает `LoadLibrary("VirusDLL.dll")` в своём процессе — чтобы убедиться, что DLL правильно собрана и её `DllMain` отрабатывает, прежде чем тестировать удалённую инъекцию.

### ProtectedProcess

Защищённая версия процесса-жертвы. Реализует метод предотвращения загрузки сторонних DLL через атрибуты создания процесса.

#### Как работает защита

Windows позволяет задать политику митигации для дочернего процесса при его создании через `CreateProcessA`. Для этого используется цепочка вызовов:

```
InitializeProcThreadAttributeList   ← выделяем и инициализируем список атрибутов
        ↓
UpdateProcThreadAttribute           ← записываем в список политику BLOCK_NON_MICROSOFT_BINARIES
        ↓
CreateProcessA(..., EXTENDED_STARTUPINFO_PRESENT, ...)  ← передаём список через STARTUPINFOEXA
```

Политика `PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON` заставляет Windows отклонять любую попытку загрузить DLL, у которой нет действительной подписи Microsoft. Проверка выполняется ядром при каждом вызове `NtMapViewOfSection` — ещё до того, как образ DLL попадёт в адресное пространство процесса. Обойти её из пользовательского режима без модификации ядра невозможно.

#### Ограничение и обход через самоперезапуск

`UpdateProcThreadAttribute` применяется только к **создаваемому** процессу — уже запущенный процесс таким способом защитить нельзя. Чтобы процесс защитил сам себя, используется следующий приём:

```
ProtectedProcess.exe              ← запуск без аргументов
  │
  │  argv[1] != "xakep"
  │  GetModuleFileNameA → получаем абсолютный путь к себе
  │  sprintf_s → "<путь>\ProtectedProcess.exe xakep"
  │
  └─► CreateProcessA(
            cmdline = "<путь> xakep",
            flags   = EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
            attrs   = { BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON }
      )
            │
            └─► ProtectedProcess.exe xakep    ← новый процесс, уже под защитой
                  argv[1] == "xakep" → переходит к рабочему циклу

  CloseHandle(hProcess), CloseHandle(hThread)
  return 0  ← родитель завершается, его консоль закрывается
```

Аргумент `xakep` выступает маркером: увидев его, процесс понимает, что запущен с нужными атрибутами и может приступать к работе. `CREATE_NEW_CONSOLE` гарантирует, что дочерний процесс откроет собственное окно, а окно родителя закроется сразу после `return 0`.

#### Что происходит при попытке инъекции

```
DLLInjectorAsProcess.exe <PID защищённого процесса>

  OpenProcess         → успех (права на VM и потоки не ограничены этой политикой)
  VirtualAllocEx      → успех
  WriteProcessMemory  → успех
  CreateRemoteThread(LoadLibraryA, <адрес строки с путём к DLL>)
        │
        └─► Windows пытается загрузить DLL в адресное пространство
              NtMapViewOfSection проверяет подпись образа
              подпись отсутствует / не Microsoft
              → STATUS_ACCESS_DISABLED_BY_POLICY
              → CreateRemoteThread возвращает NULL
              → GetLastError() == 1260 (ERROR_ACCESS_DISABLED_BY_POLICY)
```

MessageBox не появляется — DLL так и не попала в адресное пространство жертвы.

#### Исключение

DLL с действительной подписью Microsoft (например, `ntdll.dll`, `kernel32.dll`, системные компоненты) загружаются без ограничений — политика их не затрагивает.

---

### Prize.html

Фишинговая страница: кнопка → JavaScript через `ActiveXObject("WScript.Shell")` вызывает `Rundll32.exe` с инжектором и нужным PID. Работает только в **Internet Explorer** — в современных браузерах ActiveX заблокирован.

---

## 5. Сборка

**Требования:** 
- MSVC
- CMAKE v.3.10+

```
cmake -B build -G Ninja/"NMake Makefiles" -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

Бинарники появятся в `build/**`.

---

## 6. Запуск

Повышение прав не нужно — достаточно, чтобы инжектор и жертва были запущены от одного пользователя.

**1. Проверить, что VirusDLL работает**

```
build\DLLLoader.exe
```

Появится MessageBox с заголовком `DLLLoader.exe` — DLL в порядке.

**2. Запустить жертву**

```
build\TargetProcess.exe
```

**3. Инъекция через .exe**

```
build\DLLInjectorAsProcess.exe <PID>
```

В окне `TargetProcess.exe` выскочит MessageBox — инъекция сработала.

**4. Инъекция через Rundll32**

```
Rundll32.exe  <path>/DllInjectorAsDll.dll HelperFunc <PID>
```

**5. Через браузер (только IE)**

Открыть `Prize.html` в Internet Explorer, поменять PID в скрипте на актуальный, нажать кнопку.

---

**6. Демонстрация защиты**

Убить все запущенные экземпляры `TargetProcess.exe` — в защищённом сценарии он не нужен, чтобы не перепутать PID.

Убедиться, что `VirusDLL.dll` лежит рядом с `ProtectedProcess.exe` (оба в `build\`) — инжектор ищет её по относительному пути.

Запустить защищённый процесс:

```
build\ProtectedProcess.exe
```

Первое окно сразу закроется, выведя:

```
[!] Local Process Is Not Protected With The Block Dll Policy
[i] Protected Process Created With PID <N>
[i] Parent exiting — child has its own console window
```

Откроется второе окно — это уже защищённый дочерний процесс:

```
[+] Process Is Now Protected With The Block Dll Policy
PID: <N>
Processing - 0
Processing - 1
...
```

Провести попытка инжектирования
```
build\DLLInjectorAsProcess.exe <N>
```

После должна выскочить ошибка WINDOWS о невозможности применения стороннего .dll

MessageBox не появится — DLL заблокирована на уровне ядра до попадания в адресное пространство.
