#pragma once
#include <android/log.h>
#include <cstdio>
#include <cstdarg>
#include <mutex>
#include "includes/opts.h"

#define LOG_TAG "midnight"
#define LOG_FILE_PATH "/storage/emulated/0/Android/data/" PACKAGE_NAME "/files/midnight.log"

inline void WriteToFile(const char* level, const char* fmt, ...) {
    static std::mutex logMutex;
    std::lock_guard<std::mutex> lock(logMutex);

    FILE* file = std::fopen(LOG_FILE_PATH, "a");
    if (file) {
        std::fprintf(file, "[%s] [%s]: ", level, LOG_TAG);
        
        va_list args;
        va_start(args, fmt);
        std::vfprintf(file, fmt, args);
        va_end(args);
        
        std::fprintf(file, "\n");
        std::fclose(file);
    }
}

#define LOGI(...) do { \
    if constexpr (ENABLE_LOGS) { \
        __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__); \
        WriteToFile("INFO", __VA_ARGS__); \
    } \
} while(0)

#define LOGE(...) do { \
    __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__); \
    WriteToFile("ERROR", __VA_ARGS__); \
} while(0)
