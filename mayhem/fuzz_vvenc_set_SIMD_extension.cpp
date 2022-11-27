#include <stdint.h>
#include <stdio.h>
#include <climits>

#include "vvenc/vvenc.h"
#include <fuzzer/FuzzedDataProvider.h>
namespace vvenc
{
    class Exception : public std::exception
    {
    };
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string str = provider.ConsumeRandomLengthString();
    const char* cstr = str.c_str();

    try
    {
        vvenc_set_SIMD_extension(cstr);
    }
    catch (vvenc::Exception e)
    {
    }

    return 0;
}