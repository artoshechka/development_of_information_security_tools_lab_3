/// @file DLLLoader/Source.cpp
/// @brief Утилита для проверки корректности сборки VirusDLL.
///        Загружает библиотеку в собственный процесс — если DllMain отработает,
///        появится MessageBox с именем текущего процесса.

#include <Windows.h>
#include <winerror.h>

int main()
{
    LoadLibrary("VirusDLL.dll");
    return 0;
}
