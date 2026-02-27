// TP
var result = 'hello'.substring(1).substring(2).substring(3).substring(4);
var replaced = 'hello world'.replaceAll('o', '0').replaceAll('l', '1').replaceAll('e', '3').replaceAll('h', '4');
var joined = ['apple', 'banana', 'cherry'].join(", ").join(" - ").join(": ").join("mphf");
var codeUnit = 'hello'.codeUnitAt(0).codeUnitAt(1).codeUnitAt(2).codeUnitAt(3);

// FP
var result = 'hello'.substring(1).substring(2).substring(3);
var replaced = 'hello world'.replaceAll('o', '0').replaceAll('l', '1')._replaceAll('e', '3').replaceAll('h', '4');
var split = 'apple,banana,orange'.split(',');
var joined = ['apple', 'banana'].join(", ");
var codeUnit = 'hello'.xcodeUnitAt(0).xcodeUnitAt(1).xcodeUnitAt(2).xcodeUnitAt(3).xcodeUnitAt(4);