/// @file ProtectedProcess/Source.cpp
/// @brief Процесс-жертва с защитой от загрузки сторонних DLL.
///        Использует UpdateProcThreadAttribute с политикой
///        BLOCK_NON_MICROSOFT_BINARIES для предотвращения инъекции.

#include <Windows.h>
#include <stdio.h>

/// Если определено — процесс защищает сам себя через самоперезапуск.
/// Если убрать — запускает с защитой внешний процесс (RuntimeBroker.exe).
#define LOCAL_BLOCKDLLPOLICY

/// Аргумент командной строки, служащий маркером защищённого запуска.
/// Процесс проверяет его наличие в argv, чтобы понять, был ли он уже
/// запущен с нужными атрибутами митигации.
#define STOP_ARG "xakep"

/// @brief Запускает процесс с политикой блокировки сторонних DLL.
///
/// Создаёт список атрибутов процесса с митигацией
/// PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON,
/// после чего запускает указанный исполняемый файл через CreateProcessA.
/// Двойной вызов InitializeProcThreadAttributeList стандартен: первый —
/// получение нужного размера буфера, второй — фактическая инициализация.
///
/// @param lpProcessPath  Командная строка запускаемого процесса.
/// @param dwProcessId    [out] PID созданного процесса.
/// @param hProcess       [out] Дескриптор созданного процесса.
/// @param hThread        [out] Дескриптор главного потока созданного процесса.
/// @return TRUE при успехе, FALSE при любой ошибке.
BOOL CreateProcessWithBlockDllPolicy(IN LPSTR lpProcessPath, OUT DWORD* dwProcessId, OUT HANDLE* hProcess,
                                     OUT HANDLE* hThread)
{
    /// STARTUPINFOEXA расширяет обычный STARTUPINFO полем lpAttributeList —
    /// именно через него передаётся список атрибутов с политикой митигации.
    STARTUPINFOEXA SiEx = {0};
    PROCESS_INFORMATION Pi = {0};

    /// Размер буфера для LPPROC_THREAD_ATTRIBUTE_LIST — заполняется первым
    /// вызовом InitializeProcThreadAttributeList.
    SIZE_T sAttrSize = NULL;

    if (lpProcessPath == NULL) return FALSE;

    /// Обнуляем структуры перед использованием во избежание мусорных данных.
    RtlSecureZeroMemory(&SiEx, sizeof(STARTUPINFOEXA));
    RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

    /// cb должен содержать размер структуры — обязательное требование WinAPI.
    SiEx.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    /// Флаг сигнализирует CreateProcess, что мы передаём расширенный
    /// STARTUPINFOEXA, а не обычный STARTUPINFO, и список атрибутов нужно читать.
    SiEx.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT;

    /// Первый вызов с NULL-буфером — только узнаём нужный размер.
    /// Реальной инициализации не происходит, ошибку игнорируем намеренно.
    InitializeProcThreadAttributeList(NULL, 1, NULL, &sAttrSize);

    /// Выделяем буфер нужного размера на куче с обнулением.
    LPPROC_THREAD_ATTRIBUTE_LIST pAttrBuf =
        (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sAttrSize);

    /// Второй вызов — фактическая инициализация структуры в выделенном буфере.
    /// Параметр 1 — количество атрибутов, которые будем добавлять.
    if (!InitializeProcThreadAttributeList(pAttrBuf, 1, NULL, &sAttrSize))
    {
        printf("[!] InitializeProcThreadAttributeList Failed With Error : %d\n", GetLastError());
        return FALSE;
    }

    /// Политика ALWAYS_ON запрещает ядру отображать в адресное пространство
    /// процесса любой PE-образ без действительной подписи Microsoft.
    /// Проверка происходит в NtMapViewOfSection до того, как DLL попадает в память.
    DWORD64 dwPolicy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

    /// Записываем политику митигации в список атрибутов.
    /// PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY — идентификатор атрибута политики безопасности.
    if (!UpdateProcThreadAttribute(pAttrBuf, NULL, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &dwPolicy, sizeof(DWORD64),
                                   NULL, NULL))
    {
        printf("[!] UpdateProcThreadAttribute Failed With Error : %d\n", GetLastError());
        return FALSE;
    }

    /// Передаём заполненный список атрибутов в расширенную структуру запуска.
    SiEx.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)pAttrBuf;

    if (!CreateProcessA(NULL,           /// имя исполняемого файла берётся из lpCommandLine
                        lpProcessPath,  /// командная строка: путь + аргументы
                        NULL,           /// атрибуты безопасности процесса — по умолчанию
                        NULL,           /// атрибуты безопасности потока — по умолчанию
                        FALSE,          /// дескрипторы не наследуются
                        /// EXTENDED_STARTUPINFO_PRESENT — читать lpAttributeList из STARTUPINFOEXA.
                        /// CREATE_NEW_CONSOLE — дочерний процесс получает собственное консольное окно,
                        /// поэтому закрытие родителя не уничтожает консоль ребёнка.
                        EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
                        NULL,  /// переменные среды наследуются от родителя
                        NULL,  /// рабочий каталог наследуется от родителя
                        &SiEx.StartupInfo, &Pi))
    {
        printf("[!] CreateProcessA Failed With Error : %d\n", GetLastError());
        return FALSE;
    }

    /// Возвращаем идентификаторы созданного процесса вызывающей стороне.
    *dwProcessId = Pi.dwProcessId;
    *hProcess = Pi.hProcess;
    *hThread = Pi.hThread;

    /// Освобождаем список атрибутов — он больше не нужен после CreateProcess.
    DeleteProcThreadAttributeList(pAttrBuf);
    HeapFree(GetProcessHeap(), 0, pAttrBuf);

    if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
        return TRUE;
    else
        return FALSE;
}

/// @brief Точка входа.
///
/// Логика самозащиты:
///   - Если STOP_ARG отсутствует в argv — перезапускает себя с защитой.
///   - Если STOP_ARG присутствует — процесс уже защищён, запускает рабочий цикл.
int main(int argc, char* argv[])
{
    DWORD dwProcessId = NULL;
    HANDLE hProcess = NULL, hThread = NULL;

#ifdef LOCAL_BLOCKDLLPOLICY
    /// Наличие STOP_ARG означает, что этот экземпляр был запущен родителем
    /// уже с атрибутами митигации — можно переходить к рабочей логике.
    if (argc == 2 && (strcmp(argv[1], STOP_ARG) == 0))
    {
        /// Небольшая пауза, чтобы родитель успел завершиться и вывод не перемешался.
        Sleep(500);
        printf("[+] Process Is Now Protected With The Block Dll Policy\n");
        printf("PID: %lu\n", GetCurrentProcessId());

        int i = 0;
        while (TRUE)
        {
            printf("Processing - %d\n", i++);
            Sleep(1000);
        }
    } else
    {
        /// STOP_ARG отсутствует — текущий экземпляр запущен без защиты.
        /// Получаем абсолютный путь к собственному исполняемому файлу.
        printf("[!] Local Process Is Not Protected With The Block Dll Policy\n");

        CHAR pcFilename[MAX_PATH * 2];
        if (!GetModuleFileNameA(NULL, (LPSTR)&pcFilename, MAX_PATH * 2))
        {
            printf("[!] GetModuleFileNameA Failed With Error : %d\n", GetLastError());
            return -1;
        }

        /// Формируем командную строку: "<абсолютный путь к exe> xakep".
        /// Запас 0xFF байт компенсирует пробел-разделитель и возможное выравнивание.
        DWORD dwBufferSize = (DWORD)(lstrlenA(pcFilename) + lstrlenA(STOP_ARG) + 0xFF);
        CHAR* pcBuffer = (CHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufferSize);
        if (!pcBuffer) return -1;

        sprintf_s(pcBuffer, dwBufferSize, "%s %s", pcFilename, STOP_ARG);

        /// Запускаем защищённую копию себя. Дочерний процесс увидит STOP_ARG
        /// и перейдёт в ветку рабочего цикла выше.
        if (!CreateProcessWithBlockDllPolicy(pcBuffer, &dwProcessId, &hProcess, &hThread))
        {
            HeapFree(GetProcessHeap(), 0, pcBuffer);
            return -1;
        }

        HeapFree(GetProcessHeap(), 0, pcBuffer);

        /// Закрываем дескрипторы: родитель не будет ждать завершения ребёнка.
        CloseHandle(hProcess);
        CloseHandle(hThread);
        printf("[i] Protected Process Created With PID %d\n", dwProcessId);
        printf("[i] Press any key to close this window...\n");
        getchar();
    }
#endif

#ifndef LOCAL_BLOCKDLLPOLICY
    /// Режим запуска внешнего процесса с защитой (LOCAL_BLOCKDLLPOLICY не определён).
    if (!CreateProcessWithBlockDllPolicy((LPSTR) "C:\\Windows\\System32\\RuntimeBroker.exe", &dwProcessId, &hProcess,
                                         &hThread))
    {
        return -1;
    }
    printf("[i] Process Created With Pid %d\n", dwProcessId);
#endif

    return 0;
}
