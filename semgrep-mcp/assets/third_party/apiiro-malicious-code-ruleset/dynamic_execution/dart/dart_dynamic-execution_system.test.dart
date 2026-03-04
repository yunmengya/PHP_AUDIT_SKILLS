// TP
var result = await Process.run('dart', ['-e', '...']);
var result = Process.runSync('dart', ['-e', '...']);
Process.start('dart', ['-e', '...']);

// FP
Process.execute('dart', ['--version']); // 'execute' is not a match
var systemProcess = Process;
systemProcess.invoke('dart', ['script.dart']); // 'invoke' is not a match
proc.runOther('dart', ['script.dart']); // 'runOther' is not a match
var r = Process.run('dart', ['--version']);
Process.runSync('dart', ['-c', 'code.dart']);
Process.start('dart', ['script.dart']);
var proc = Process;
proc.run('dart', ['args']);
proc.runSync('dart', ['args']);
proc.start('dart', ['args']);
