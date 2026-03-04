// TP

"scala -e ..." !!

val cmd = "scala -e .."
cmd.!

// FP

val cmd = "scala -e 'println(\"not executed\")'"
println(cmd)
