/// @file TargetProcess/Source.cpp
/// @brief Процесс-жертва. Выводит свой PID и запускает бесконечный счётчик —
///        живая цель для демонстрации DLL-инъекции.

#include <Windows.h>
#include <stdio.h>

int main()
{
    DWORD pid = GetCurrentProcessId();
    printf("PID: %lu\n", pid);

    int i = 0;
    while (true)
    {
        printf("Processing - %d\n", i++);
        Sleep(1000);
    }
    return 0;
}
