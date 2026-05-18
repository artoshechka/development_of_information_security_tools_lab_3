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

Реализованный метод: `UpdateProcThreadAttribute` + `PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON`

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

Это то, что мы внедряем. Как только DLL загружается в чужой процесс, срабатывает `DllMain` с событием `DLL_PROCESS_ATTACH`, который вызывает `Attack()`. Та спрашивает у Windows имя текущего процесса через `GetModuleBaseNameA` и показывает `MessageBox` с этим именем в заголовке — наглядное доказательство, что DLL оказалась там, где нужно.

### TargetProcess

Бесконечный цикл, который раз в секунду печатает счётчик. Никакой полезной логики, только что-то живое, в чём можно наблюдать эффект инъекции. Именно его PID передаётся инжектору.

### DLLInjectorAsProcess

Консольная программа, которая принимает PID жертвы первым аргументом и выполняет все четыре шага инъекции.

```
DLLInjectorAsProcess.exe <PID>
```

`VirusDLL.dll` должна лежать рядом или быть доступна через `PATH`.

### DllInjectorAsDll

Та же логика инъекции, упакованная в DLL. Запускается через `Rundll32.exe` — системную утилиту Windows — без отдельного исполняемого файла. Экспортирует функцию `HelperFunc`, которой Rundll32 передаёт PID жертвы строкой:

```
Rundll32.exe C:\Temp\DllInjectorAsDll.dll HelperFunc <PID>
```

### DLLLoader

Не инжектор. Вызывает `LoadLibrary("VirusDLL.dll")` в своём процессе — чтобы убедиться, что DLL правильно собрана и её `DllMain` отрабатывает, прежде чем тестировать удалённую инъекцию.

### ProtectedProcess

Защищённая версия процесса-жертвы. Использует `UpdateProcThreadAttribute` с политикой `PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON`, которая запрещает загрузку DLL без действительной подписи Microsoft.

Проблема: `UpdateProcThreadAttribute` применяется только к дочернему процессу, запускаемому через `CreateProcess`, — к уже работающему процессу её не применить.

**Решение — самоперезапуск:**

```
ProtectedProcess.exe          ← запускается без аргументов
  │  видит: STOP_ARG отсутствует
  │  читает свой путь через GetModuleFileNameA
  └─► CreateProcessA("<путь> xakep", ..., атрибуты с митигацией)
          │
          └─► ProtectedProcess.exe xakep   ← этот экземпляр уже под защитой
                видит: argv[1] == "xakep"
                запускает рабочий цикл
```

Первый экземпляр после порождения дочернего завершается. Дочерний работает в защищённом виртуальном адресном пространстве — `CreateRemoteThread` + `LoadLibraryA` вернёт ошибку `ERROR_ACCESS_DISABLED_BY_POLICY` (код 1260).

Единственное исключение: DLL, подписанные самой Microsoft, всё равно загружаются беспрепятственно.

---

### Prize.html

Фишинговая страница: кнопка → JavaScript через `ActiveXObject("WScript.Shell")` вызывает `Rundll32.exe` с инжектором и нужным PID. Работает только в **Internet Explorer** — в современных браузерах ActiveX заблокирован.

---

## 5. Сборка

**Требования:** Windows 10/11, [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022) с компонентом «Разработка классических приложений на C++», [CMake 3.10+](https://cmake.org/download/).

Открыть **Developer Command Prompt for VS Build Tools** и выполнить из корня проекта:

```
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

Если Ninja не установлен — использовать NMake (идёт в комплекте с Build Tools):

```
cmake -B build -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

Бинарники появятся в `build/`.

> Обычный `cmd` или PowerShell не подойдут — только Developer Command Prompt, он настраивает окружение для `cl.exe`.

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

Запустить защищённый процесс:

```
build\ProtectedProcess.exe
```

Первый экземпляр выведет:

```
[!] Local Process Is Not Protected With The Block Dll Policy
[i] Protected Process Created With PID <N>
```

и завершится. Второй экземпляр выведет:

```
[+] Process Is Now Protected With The Block Dll Policy
PID: <N>
Processing - 0
Processing - 1
...
```

Попытка инъекции в PID `<N>`:

```
build\DLLInjectorAsProcess.exe <N>
```

`CreateRemoteThread` вернёт ошибку 1260 (`ERROR_ACCESS_DISABLED_BY_POLICY`) — DLL не загрузится, MessageBox не появится.
