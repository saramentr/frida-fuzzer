import * as fuzz from "../fuzz/index.js";

// Actually Java fuzzing is WIP, works only of the target module is AOT compiled

// To start the fuzzing loop manually when Java is avaiable
fuzz.set_manual_loop_start(true);

var arg = function () {

  Java.perform(function () {

    // Find the MainActivity instance
    var activity = null;
    Java.choose('com.example.seccon2015.rock_paper_scissors.MainActivity', {
      onMatch: function (instance) {
        activity = instance;
        return "stop";
      },
      onComplete: function () {}
    });
    
    // Clone to enable traps: 'all', this is mandatory
    var test_java_func_btn = activity.calc.clone({ traps: 'all' });

    fuzz.fuzzer_test_one_input = function (/* Uint8Array */ payload) {

      //var str = fuzz.utils.uint8arr_to_str(payload);
      
      test_java_func_btn.call(activity);

    }

    /* Start the fuzzing loop when the button is clicked */
    activity.sendMessage.implementation = function () {
    
      /* Manually start loop so that we ensure to call fuzzer_test_one_input
       in the Java perform context */
      fuzz.fuzzing_loop();
    
    }

  });

}
fuzz.set_init_callback(arg)
console.log (" >> Agent loaded!");
