const devp2p = require('ethereumjs-devp2p')
const EthereumTx = require('ethereumjs-tx')
const EthereumBlock = require('ethereumjs-block')
const LRUCache = require('lru-cache')
const ms = require('ms')
const assert = require('assert')
const { randomBytes } = require('crypto')
const rlp = require('rlp-encoding')
const log = require('./chalk');
const BigNumber = require("bignumber.js");
const PRIVATE_KEY = randomBytes(32)
const DAO_FORK_SUPPORT = true

const BOOTNODES = require('ethereum-common').bootstrapNodes.map((node) => {
    return {
        address: node.ip,
        udpPort: node.port,
        tcpPort: node.port
    }
})

const ETH_1920000 = '4985f5ca3d2afbec36529aa96f74de3cc10a2a4a6c44f2157a57d2c6059a11bb'
const ETH_1920000_HEADER = rlp.decode(Buffer.from('f9020da0a218e2c611f21232d857e3c8cecdcdf1f65f25a4477f98f6f47e4063807f2308a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794bcdfc35b86bedf72f0cda046a3c16829a2ef41d1a0c5e389416116e3696cce82ec4533cce33efccb24ce245ae9546a4b8f0d5e9a75a07701df8e07169452554d14aadd7bfa256d4a1d0355c1d174ab373e3e2d0a3743a026cf9d9422e9dd95aedc7914db690b92bab6902f5221d62694a2fa5d065f534bb90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008638c3bf2616aa831d4c008347e7c08301482084578f7aa88d64616f2d686172642d666f726ba05b5acbf4bf305f948bd7be176047b20623e1417f75597341a059729165b9239788bede87201de42426', 'hex'))
const ETC_1920000 = '94365e3a8c0b35089c1d1195081fe7489b528a84b22199c916180db8b28ade7f'
let bestHash = Buffer.from('d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3', 'hex')
let genesisHash = Buffer.from('d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3', 'hex')
let totalDifficulty = devp2p._util.int2buffer(17179869184) // total difficulty in genesis block
const getPeerAddr = (peer) => `${peer._socket.remoteAddress}:${peer._socket.remotePort}`

// DPT
const dpt = new devp2p.DPT(PRIVATE_KEY, {
    refreshInterval: 30000,
    endpoint: {
        address: '0.0.0.0',
        udpPort: null,
        tcpPort: null
    }
})

dpt.on('error', (err) => log.error(`DPT error: ${err}`))

// RLPx
const rlpx = new devp2p.RLPx(PRIVATE_KEY, {
    dpt: dpt,
    maxPeers: 1000,
    capabilities: [
        devp2p.ETH.eth63,
        devp2p.ETH.eth62
    ],
    listenPort: null
})

rlpx.on('error', (err) => log.error(`RLPx error: ${err.stack || err}`))

rlpx.on('peer:added', (peer) => {
    const addr = getPeerAddr(peer)
    const eth = peer.getProtocols()[0]
    const requests = { headers: [], bodies: [] }

    const clientId = peer.getHelloMessage().clientId
    eth.sendStatus({
        networkId: 1,
        td: totalDifficulty,
        bestHash: bestHash,
        genesisHash: genesisHash
    })

    // check DAO
    let forkDrop = null
    let forkVerified = false
    eth.once('status', () => {
        if (DAO_FORK_SUPPORT === null) return
        eth.sendMessage(devp2p.ETH.MESSAGE_CODES.GET_BLOCK_HEADERS, [1920000, 1, 0, 0])
        forkDrop = setTimeout(() => {
            peer.disconnect(devp2p.RLPx.DISCONNECT_REASONS.USELESS_PEER)
        }, ms('15s'))
        peer.once('close', () => clearTimeout(forkDrop))
    })
    eth.on('status', (_status) => {
        let _td = new BigNumber('0x' + _status.td.toString('hex'))
        let _curTd = new BigNumber('0x' + totalDifficulty.toString('hex'))
        if (_td.gt(_curTd)) {
            totalDifficulty = _status.td
            bestHash = _status.bestHash
            log.success(`Difficulty changed ${_td.toString()} bestHash ${bestHash.toString('hex')}`)
        }
    })
    eth.on('message', (code, payload) => {
        switch (code) {
            case devp2p.ETH.MESSAGE_CODES.NEW_BLOCK_HASHES:
                if (DAO_FORK_SUPPORT !== null && !forkVerified) break
                for (let item of payload) {
                    const blockHash = item[0]
                    if (blocksCache.has(blockHash.toString('hex'))) continue
                    setTimeout(() => {
                        eth.sendMessage(devp2p.ETH.MESSAGE_CODES.GET_BLOCK_HEADERS, [blockHash, 1, 0, 0])
                        requests.headers.push(blockHash)
                    }, ms('0.25s'))
                }
                break

            case devp2p.ETH.MESSAGE_CODES.TX:
                break

            case devp2p.ETH.MESSAGE_CODES.GET_BLOCK_HEADERS:
                const headers = []
                    // hack
                if (DAO_FORK_SUPPORT && devp2p._util.buffer2int(payload[0]) === 1920000) {
                    headers.push(ETH_1920000_HEADER)
                }

                eth.sendMessage(devp2p.ETH.MESSAGE_CODES.BLOCK_HEADERS, headers)
                break

            case devp2p.ETH.MESSAGE_CODES.BLOCK_HEADERS:
                if (DAO_FORK_SUPPORT !== null && !forkVerified) {
                    if (payload.length !== 1) {
                        console.log(`${addr} expected one header for DAO fork verify (received: ${payload.length})`)
                        break
                    }

                    const expectedHash = DAO_FORK_SUPPORT ? ETH_1920000 : ETC_1920000
                    const header = new EthereumBlock.Header(payload[0])
                    if (header.hash().toString('hex') === expectedHash) {
                        clearTimeout(forkDrop)
                        forkVerified = true
                    }
                } else {
                    if (payload.length > 1) {
                        console.log(`${addr} not more than one block header expected (received: ${payload.length})`)
                        break
                    }

                    const blockHash = requests.headers.shift()
                    const header = new EthereumBlock.Header(payload[0])
                    if (header.hash().equals(blockHash)) {
                        eth.sendMessage(devp2p.ETH.MESSAGE_CODES.GET_BLOCK_BODIES, [blockHash])
                        requests.bodies.push(header)
                    } else {
                        console.log(`${addr} received wrong block header ${header.hash().toString('hex')} / ${blockHash.toString('hex')}`)
                    }
                }
                break

            case devp2p.ETH.MESSAGE_CODES.GET_BLOCK_BODIES:
                eth.sendMessage(devp2p.ETH.MESSAGE_CODES.BLOCK_BODIES, [])
                break

            case devp2p.ETH.MESSAGE_CODES.BLOCK_BODIES:
                if (DAO_FORK_SUPPORT !== null && !forkVerified) break
                if (payload.length !== 1) {
                    console.log(`${addr} not more than one block body expected (received: ${payload.length})`)
                    break
                }
                const header = requests.bodies.shift()
                const block = new EthereumBlock([header.raw, payload[0][0], payload[0][1]])
                isValidBlock(block, (result) => {
                    if (result) onNewBlock(block, peer)
                })
                break

            case devp2p.ETH.MESSAGE_CODES.NEW_BLOCK:
                if (DAO_FORK_SUPPORT !== null && !forkVerified) break
                const newBlock = new EthereumBlock(payload[0])
                isValidBlock(newBlock, (result) => {
                    if (result) onNewBlock(newBlock, peer)
                })
                break

            case devp2p.ETH.MESSAGE_CODES.GET_NODE_DATA:
                eth.sendMessage(devp2p.ETH.MESSAGE_CODES.NODE_DATA, [])
                break

            case devp2p.ETH.MESSAGE_CODES.NODE_DATA:
                break

            case devp2p.ETH.MESSAGE_CODES.GET_RECEIPTS:
                eth.sendMessage(devp2p.ETH.MESSAGE_CODES.RECEIPTS, [])
                break

            case devp2p.ETH.MESSAGE_CODES.RECEIPTS:
                break
        }
    })
})

rlpx.on('peer:removed', (peer, reason, disconnectWe) => {
    const who = disconnectWe ? 'we disconnect' : 'peer disconnect'
    const total = rlpx.getPeers().length
})

rlpx.on('peer:error', (peer, err) => {
    if (err.code === 'ECONNRESET') return

    if (err instanceof assert.AssertionError) {
        const peerId = peer.getId()
        if (peerId !== null) dpt.banPeer(peerId, ms('5m'))
        return
    }

    log.error(`Peer error (${getPeerAddr(peer)}): ${err.stack || err}`);
})
let txCallback = (tx) => {}

function startListening(_txCallback) {
    txCallback = _txCallback
    for (let bootnode of BOOTNODES) {
        dpt.bootstrap(bootnode).catch((err) => {
            //log.error(`DPT bootstrap error: ${err.stack || err}`)
        })
    }
}

const txCache = new LRUCache({ maxAge: ms('1d') })

function onNewTx(tx, peer) {
    const txHashHex = '0x' + tx.hash().toString('hex')
    if (txCache.has(txHashHex)) return
    txCache.set(txHashHex, tx.serialize().toString('hex'))
    txCallback(tx)
}
const blocksCache = new LRUCache({ max: 100 })

function onNewBlock(block, peer) {
    const blockHashHex = block.hash().toString('hex')
    if (blocksCache.has(blockHashHex)) return

    blocksCache.set(blockHashHex, true)
    console.log(`new block: ${blockHashHex} (from ${getPeerAddr(peer)})`)
    let _count = 0;
    for (let tx of block.transactions) {
        let _hash = '0x' + tx.hash().toString('hex');
        if (txCache.has(_hash)) _count++;
        txCache.del(_hash);
    }
    log.success(`${_count} Transactions were mined from the pool`)
}

function deleteTxFromCache(hash) {
    txCache.del(hash);
}

function isValidTx(tx) {
    return tx.validate(false)
}

function isValidBlock(block, cb) {
    if (!block.validateUnclesHash()) cb(false)
    if (!block.transactions.every(isValidTx)) cb(false)
    block.genTxTrie(() => {
        try {
            cb(block.validateTransactionsTrie())
        } catch (err) {
            cb(false)
        }
    })
}
setInterval(() => {
    const peersCount = dpt.getPeers().length
    const openSlots = rlpx._getOpenSlots()
    const queueLength = rlpx._peersQueue.length
    const queueLength2 = rlpx._peersQueue.filter((o) => o.ts <= Date.now()).length
    log.info(`Total nodes in DPT: ${peersCount}, open slots: ${openSlots}, queue: ${queueLength} / ${queueLength2}`)
    let _curTd = new BigNumber('0x' + totalDifficulty.toString('hex'))
    log.info(`Difficulty ${_curTd.toString()} bestHash ${bestHash.toString('hex')}`)
}, ms('10s'))
setInterval(() => {
    let txArr = [];
    txCache.forEach((value, key) => {
        txArr.push(rlp.decode(Buffer.from(value, 'hex')));
    });
    // if (txArr.length > 1000)
    //     txArr.push(rlp.decode(Buffer.from('f869378504a817c800825208947cb57b5a97eabe94205c07890be4c1ad31e486a885e8d4a510008025a0336c33f87edbc5e5139a537cc85975300e560426ecb76a6879cc78991ffa306aa06bd05781aaca134bd9c4264cdd5dc90432cd6df65278d917856c9c4fcd4f6c61', 'hex')));

    if (!txArr.length) return;
    let peers = rlpx.getPeers();
    log.info(`Num Peers ${peers.length} num TXs ${txArr.length}`)
    for (let id in peers) {
        const _eth = peers[id].getProtocols()[0];
        _eth.sendStatus({
            networkId: 1,
            td: totalDifficulty,
            bestHash: bestHash,
            genesisHash: genesisHash
        })
        let i, j, temparray, chunk = 40;
        for (i = 0, j = txArr.length; i < j; i += chunk) {
            temparray = txArr.slice(i, i + chunk);
            _eth.sendMessage(devp2p.ETH.MESSAGE_CODES.TX, temparray);
        }
    }
}, ms('10s'));
module.exports = {
    startListening: startListening,
    deleteTxFromCache: deleteTxFromCache
}
