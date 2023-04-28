/*

   frida-fuzzer - frida agent instrumentation
   ------------------------------------------

   Written and maintained by Andrea Fioraldi <andreafioraldi@gmail.com>
   Based on American Fuzzy Lop by Michal Zalewski

   Copyright 2019 Andrea Fioraldi. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

//exports.MAP_SIZE = 65536; // 2^16, AFL default
export let MAP_SIZE = 32768; // 2^15, small APIs doesn't require a large map
//exports.MAP_SIZE = 16384; // 2^14, small APIs doesn't require a large map

export var MAX_FILE = 1024*6;
// after timeout abort fuzzing
export var TIMEOUT = 10*1000; // 10 seconds

export var HAVOC_STACK_POW2 = 7;

export var HAVOC_CYCLES = 256;
export var SPLICE_HAVOC = 32;

export var SPLICE_CYCLES = 15;

export var HAVOC_BLK_SMALL  = 32;
export var HAVOC_BLK_MEDIUM = 128;
export var HAVOC_BLK_LARGE  = 1500;
export var HAVOC_BLK_XL     = 32768;

export var INTERESTING_8  = [-128, -1, 0, 1, 16, 32, 64, 100, 127];
export var INTERESTING_16 = [-32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767];
export var INTERESTING_32 = [-2147483648, -100663046, -32769, 32768, 65535, 65536, 100663045, 2147483647];

export var ARITH_MAX = 35;

export var SKIP_TO_NEW_PROB   = 99;
export var SKIP_NFAV_OLD_PROB = 95;
export var SKIP_NFAV_NEW_PROB = 75;

// The favorite testcases scoring, slowdown the fuzzer but make also it more effective
export var SKIP_SCORE_FAV = false;

export var QUEUE_CACHE_MAX_SIZE = 512*1024*1024; // 512 MB

export var UPDATE_TIME = 5*1000; // 5 seconds
