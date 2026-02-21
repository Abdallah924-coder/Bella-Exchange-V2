async function sendTelegramMessage(message) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;

  if (!token || !chatId) {
    return;
  }

  const url = `https://api.telegram.org/bot${token}/sendMessage`;
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        text: message,
        parse_mode: 'HTML'
      })
    });
    if (!response.ok) {
      const body = await response.text();
      console.error('[TELEGRAM ERROR]', response.status, body);
    }
  } catch (err) {
    console.error('[TELEGRAM ERROR]', err.message);
  }
}

async function sendTelegramProof({ fileBuffer, fileName, mimeType, caption }) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;
  if (!token || !chatId || !fileBuffer) {
    return;
  }

  const isImage = String(mimeType || '').startsWith('image/');
  const endpoint = isImage ? 'sendPhoto' : 'sendDocument';
  const url = `https://api.telegram.org/bot${token}/${endpoint}`;

  try {
    const form = new FormData();
    form.append('chat_id', chatId);
    form.append('caption', caption || 'Preuve transaction');
    if (isImage) {
      form.append('photo', new Blob([fileBuffer], { type: mimeType || 'image/jpeg' }), fileName || 'proof.jpg');
    } else {
      form.append('document', new Blob([fileBuffer], { type: mimeType || 'application/octet-stream' }), fileName || 'proof.bin');
    }
    const response = await fetch(url, { method: 'POST', body: form });
    if (!response.ok) {
      const body = await response.text();
      console.error('[TELEGRAM FILE ERROR]', response.status, body);
    }
  } catch (err) {
    console.error('[TELEGRAM FILE ERROR]', err.message);
  }
}

module.exports = { sendTelegramMessage, sendTelegramProof };
