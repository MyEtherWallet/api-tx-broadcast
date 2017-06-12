const chalk = require('chalk');
const util = require('util')
const error = function(str) {
    console.log(chalk.red(str));
}
const success = function(str) {
    console.log(chalk.green(str));
}
const info = function(str) {
	if(typeof str === 'object') console.log(chalk.yellow(util.inspect(str, false, null)))
    else console.log(chalk.yellow(str));
}
module.exports = {
    error: error,
    success: success,
    info: info
}
