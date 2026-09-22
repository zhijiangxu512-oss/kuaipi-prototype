// WeCom (企业微信) 自建应用「接收消息服务器」回调端点
// 用途：通过 URL 验证（GET echostr 回显），解锁自建应用的企业可信IP配置
// 仅处理验证握手；消息回调（POST）一律静默返回 success，不做任何业务处理
const crypto = require('crypto');

const TOKEN = process.env.WECOM_CB_TOKEN;
const AESKEY = process.env.WECOM_CB_AESKEY; // 43 chars
const CORPID = process.env.WECOM_CORPID;

function decryptAES(encryptedBase64) {
  const key = Buffer.from(AESKEY + '=', 'base64'); // 43 + '=' = 44 chars -> 32 bytes
  const iv = Buffer.alloc(16, 0); // zero IV, WeCom spec
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  decipher.setAutoPadding(false);
  let decrypted = Buffer.concat([decipher.update(encryptedBase64, 'base64'), decipher.final()]);
  // strip PKCS#7 padding
  const pad = decrypted[decrypted.length - 1];
  if (pad < 1 || pad > 32) throw new Error('bad padding');
  decrypted = decrypted.slice(0, decrypted.length - pad);
  // layout: random(16B) + msg_len(4B BE) + msg + receiveid
  const msgLen = decrypted.readUInt32BE(16);
  const msg = decrypted.slice(20, 20 + msgLen).toString('utf8');
  return msg;
}

function verifySignature(token, timestamp, nonce, encrypt, signature) {
  const sha1 = crypto.createHash('sha1');
  sha1.update([token, timestamp, nonce, encrypt].sort().join(''));
  return sha1.digest('hex') === signature;
}

module.exports = async (req, res) => {
  const q = req.query || {};
  if (req.method === 'GET' && q.echostr) {
    try {
      if (!verifySignature(TOKEN, q.timestamp, q.nonce, q.echostr, q.msg_signature)) {
        return res.status(403).send('signature mismatch');
      }
      const reply = decryptAES(q.echostr);
      res.setHeader('Content-Type', 'text/plain');
      return res.send(reply);
    } catch (e) {
      return res.status(500).send('decrypt failed');
    }
  }
  // POST message callbacks / non-verify requests: echo success
  res.send('success');
};
