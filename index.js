var listener = require("./listener");
var rpc = require('node-json-rpc');
var config = require('./configs.json');
const EthereumTx = require('ethereumjs-tx')
const log = require('./chalk');
var options = {
    port: config.server.port,
    host: config.server.ip,
    path: config.server.path,
    strict: true
};
var serv = new rpc.Server(options);
serv.addMethod('new_tx', function(para, callback) {
    var error, result;
    if (para.length === 1) {
        try {
            let tTx = new EthereumTx(para[0]);
            if (listener.isValidTx(tTx)) {
                listener.onNewTx(tTx);
                result = { message: "TX added" };
            } else {
                error = { code: -32602, message: "Invalid TX" };
            }
        } catch (e) {
            error = { code: -32602, message: "Invalid TX" };
        }
    } else {
        error = { code: -32602, message: "Invalid params" };
    }
    callback(error, result);
});
listener.startListening((tx) => {
    log.success(`TX added: 0x${tx.hash().toString('hex')}`)
});
serv.start((error) => {
    if (error) throw error;
    else console.log('Server running ...');
});
