// Copyright (c) 2020, Cyberhaven
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <s2e/s2e.h>
#include <stdio.h>
#include "function_models.h"

#define DATA_SIZE 128

// This must be aligned on a page boundary in order to avoid extra forks
// for overlapping accesses.
char g_data[DATA_SIZE] __attribute__((aligned(DATA_SIZE)));

//function model testcase for updated null char search
static void test_null_char_search_using_strcmp(const char* str1){
    char* str2 = "A"*4096;
    s2e_make_symbolic(str2, 4096, "test_string_2");
    int res = strcmp_model(str1, str2);
    //if we did not set the last char byte to null, the function model will fail on cannot find null char
    //falling back to original call and concretize the ret 
    assert(s2e_is_symbolic(res, 4))
}

int main(int argc, char **argv) {
    char* str1 = "test string";
    test_null_char_search_using_strcmp(str1);

    if (s2e_get_path_id() != 0) {
        s2e_kill_state(0, "Terminated symbaddr1 path");
    }
}
