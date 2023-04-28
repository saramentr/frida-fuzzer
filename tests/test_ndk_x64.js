import * as config from "../fuzz/config.js";

// if you want to modify config vars you need to do it before including the fuzz module
config.set_MAP_SIZE(128);

import * as fuzz from "../fuzz/index.js";

var TARGET_MODULE = "libnative-lib.so";
var TARGET_FUNCTION = Module.findExportByName(TARGET_MODULE, "target_func");
var RET_TYPE = "void";
var ARGS_TYPES = ['pointer', 'int'];

// { traps: 'all' } is needed for stalking
var func_handle = new NativeFunction(TARGET_FUNCTION, RET_TYPE, ARGS_TYPES, { traps: 'all' });

fuzz.set_target_module(TARGET_MODULE);

let arg = function (/* Uint8Array */ payload) {

  var payload_mem = payload.buffer.unwrap();

  func_handle(payload_mem, payload.length);

}
fuzz.set_fuzzer_test_one_input(arg);
console.log (" >> Agent loaded!");
