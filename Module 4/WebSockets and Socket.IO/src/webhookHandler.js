const crypto = require('crypto');
const { handleEvent } = require('./eventHandlers');

const _processedIds = new Set();

// Verify HMAC-SHA256 signature
function verifySignature(rawBody, sigHeader) {
  if (!sigHeader) return false;

  if (!sigHeader.startsWith('sha256=')) return false;

  const received = sigHeader.slice('sha256='.length);

  if (!/^[0-9a-f]{64}$/i.test(received)) return false;

  const expected = crypto
    .createHmac('sha256', process.env.WEBHOOK_SECRET)
    .update(rawBody)
    .digest('hex');

  const expectedBuf = Buffer.from(expected, 'hex');
  const receivedBuf = Buffer.from(received, 'hex');

  if (expectedBuf.length !== receivedBuf.length) {
    return false;
  }

  return crypto.timingSafeEqual(expectedBuf, receivedBuf);
}

// Handle incoming webhook
function handleWebhook(req, res) {

  // 1. Verify signature
  if (!verifySignature(
    req.body,
    req.headers['x-webhook-signature']
  )) {
    return res.status(401).json({
      error: 'Invalid signature'
    });
  }

  // 2. Parse body after verification
  const event = JSON.parse(req.body);

  // 3. Check duplicate event
  if (_processedIds.has(event.id)) {
    return res.status(200).json({
      status: 'already_processed'
    });
  }

  // 4. Mark event as processed
  _processedIds.add(event.id);

  // 5. Acknowledge immediately
  res.status(200).json({
    status: 'received'
  });

  // 6. Process event after response
  setImmediate(() => {
    try {
      handleEvent(event);
    } catch (err) {
      console.error('handleEvent failed:', err);
    }
  });
}

module.exports = {
  handleWebhook,
  _processedIds
};