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

import * as queue from "./queue.js";
import * as stages from "./stages.js";
import * as config from "./config.js";
import * as mutator from "./mutator.js";
import * as instr from "./instrumentor.js";
import * as bitmap from "./bitmap.js";
import * as utils from "./utils.js";

/*
export var queue = queue;
export var stages = stages;
export var config = config;
export var mutator = mutator;
export var instr = instr;
export var bitmap = bitmap;
export var utils = utils;
*/
/* Define this to exclude other modules from instrumentation */
export var target_module = null;
/* MANDATORY: harness function */
export var fuzzer_test_one_input = null;
/* If true, the user has to call fuzzing_loop() manually in a callback
   (see Java example, fuzzing_loop cannot be called during script loading) */
export var manual_loop_start = false;
export var init_callback = function () {}

// by default stages are from FidgetyAFL
stages_list = [
  stages.havoc_stage,
  stages.splice_stage,
];

export var dictionary = [];

function normalize_dict () {

  var d = dictionary;
  // Accepted types are: Array Uint8Array ArrayBuffer String
  for (var i = 0; i < d.length; ++i) {
  
    if (Array.isArray(d[i]) || (d[i] instanceof ArrayBuffer))
      d[i] = new Uint8Array(d[i]);

    else if (typeof d[i] === 'string' || (d[i] instanceof String))
      d[i] = utils.str_to_uint8arr(d[i]);

    else if (!(d[i] instanceof Uint8Array))
      throw "ERROR: unsupported type for a fuzzer dictionary";
  
  }

}

export var fuzzing_loop = function () {

  if (fuzzer_test_one_input === null) {
    throw "ERROR: fuzzer_test_one_input not set! Cannot start the fuzzing loop!";
  }

  var payload = null; // Uint8Array

  if (ArrayBuffer.transfer === undefined) {
  
    var runner = function(/* ArrayBuffer */ arr_buf) {
    
      if (arr_buf.byteLength > config.MAX_FILE)
        payload = new Uint8Array(arr_buf.slice(0, config.MAX_FILE));
      else
        payload = new Uint8Array(arr_buf);
      
      // console.log(payload)

      fuzzer_test_one_input(payload);

    }
  
  } else {
  
    var runner = function(/* ArrayBuffer */ arr_buf) {
  
      if (arr_buf.byteLength > config.MAX_FILE)
        payload = new Uint8Array(arr_buf.transfer(arr_buf, config.MAX_FILE));
      else
        payload = new Uint8Array(arr_buf);
      
      // console.log(payload)

      fuzzer_test_one_input(payload);

    }
  
  }
  
  normalize_dict();
  
  Process.setExceptionHandler(function (details) {
    send({
      "event": "crash",
      "err": details,
      "stage": stages.stage_name,
      "cur": queue.cur_idx,
      "total_execs": stages.total_execs,
      "pending_fav": queue.pending_favored,
      "favs": queue.favoreds,
      "map_rate": bitmap.map_rate,
    }, payload);
    return false;
  });
  
  instr.start_tracing(Process.getCurrentThreadId(), target_module);

  console.log(" >> Dry run...");

  stages.dry_run(runner);
  queue.cull();

  console.log(" >> Starting fuzzing loop...");

  while (true) {

    var buf = queue.next();
    
    queue.cull();

    if (queue.pending_favored > 0) {

      if ((queue.cur.was_fuzzed || !queue.cur.favored) &&
          utils.UR(100) < config.SKIP_TO_NEW_PROB)
        continue;

    } else if (!queue.cur.favored && queue.size() > 10) {

      if (!queue.cur.was_fuzzed)
        if (utils.UR(100) < config.SKIP_NFAV_NEW_PROB)
          continue;
      else
        if (utils.UR(100) < config.SKIP_NFAV_OLD_PROB)
          continue;

    }
    
    // bitmap.update_bitmap_score(queue.cur);

    for(var stage of stages_list)
      stage(buf, runner);

    if (!queue.cur.was_fuzzed) {
    
      queue.cur.was_fuzzed = true;
      if (queue.cur.favored)
        queue.pending_favored--;
    
    }

  }

}

rpc.exports.loop = function () {

  init_callback();

  if (manual_loop_start) return;

  fuzzing_loop();

}
