
// Common includes and defines over the project
#pragma once
#define WIN32_LEAN_AND_MEAN
#define WINVER		 0x0A00 // _WIN32_WINNT_WIN10
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <tchar.h>
#include <crtdbg.h>
#include <intrin.h>

// IDA libs
#define USE_DANGEROUS_FUNCTIONS
#define USE_STANDARD_FILE_FUNCTIONS
#include <ida.hpp>
#include <auto.hpp>
#include <loader.hpp>
#include <typeinf.hpp>

#include <Utility.h>

#define MY_VERSION MAKE_SEMANTIC_VERSION(VERSION_RELEASE, 1, 0, 0)