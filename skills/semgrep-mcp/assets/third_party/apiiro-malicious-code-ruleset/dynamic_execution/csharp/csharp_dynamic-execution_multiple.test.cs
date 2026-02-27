using Microsoft.CodeAnalysis.CSharp.Scripting;
using Microsoft.CodeAnalysis.Scripting;
using System;
using System.Reflection;


var result = await CSharpScript.EvaluateAsync<int>("...");

var assembly = Assembly.Load("...");
var entryPoint = assembly.EntryPoint;
entryPoint.Invoke(null, null); 

var x = Assembly.Load("...");
x.EntryPoint.Invoke(null, null);

var y = Assembly.Load("...").EntryPoint;
y.Invoke(null, null);

Assembly.Load("...").EntryPoint.Invoke(null, null);
