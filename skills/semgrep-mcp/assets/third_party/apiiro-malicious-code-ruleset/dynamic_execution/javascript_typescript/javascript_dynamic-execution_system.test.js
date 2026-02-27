// TP

require('child_process').exec('node -e ...');

require('child_process').exec('node -e "..."', (err, stdout, stderr) => {});

a = 'child_process'
b = require(a)
b.exec('node -e ...')

a = require('child_process')
a.exec('node -e ...')

const { exec } = require('child_process');
exec('node -e "console.log(\'Hello World\')"');

const child_process = require('child_process');
child_process.exec('node -e "process.exit()"');

let cp = require('child_process');
cp.exec('node -e "console.log(\'Dynamic execution\')"');


// FP

const os = require('os');
os.hostname();

const exec = require('child_process').exec;
exec('ls');

let cp = require('fs');
cp.readFile('file.txt', (err, data) => {
    console.log(data);
});

const child_process = require('child_process');
child_process.spawn('node', ['-e', "console.log('Not dynamic')"]);

const child_process = require('child_process');
child_process.exec('python -c "print(\'Not Node.js\')"');

const command = 'node -v';
require('child_process').exec(command);
