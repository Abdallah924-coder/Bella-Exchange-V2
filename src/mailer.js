const nodemailer = require('nodemailer');

let transporter;

function createTransporter() {
  if (transporter) return transporter;
  const host = process.env.SMTP_HOST;
  const emailDisabled = String(process.env.SMTP_DISABLED || 'false') === 'true';
  if (emailDisabled || !host) {
    return null;
  }

  transporter = nodemailer.createTransport({
    host,
    port: Number(process.env.SMTP_PORT || 587),
    secure: String(process.env.SMTP_SECURE || 'false') === 'true',
    requireTLS: String(process.env.SMTP_REQUIRE_TLS || 'true') === 'true',
    connectionTimeout: Number(process.env.SMTP_CONNECTION_TIMEOUT || 10000),
    greetingTimeout: Number(process.env.SMTP_GREETING_TIMEOUT || 10000),
    socketTimeout: Number(process.env.SMTP_SOCKET_TIMEOUT || 20000),
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });

  return transporter;
}

async function sendEmail({ to, subject, text, html, attachments }) {
  const transporter = createTransporter();
  if (!transporter) {
    console.log('[EMAIL MOCK]', { to, subject, text });
    return { ok: true, mocked: true };
  }

  try {
    await transporter.sendMail({
      from: process.env.SMTP_FROM || 'noreply@bellaexchange.cg',
      to,
      subject,
      text,
      html,
      attachments
    });
    return { ok: true };
  } catch (err) {
    console.error('[EMAIL ERROR]', err?.code || err?.name || 'UNKNOWN', err?.message || err);
    return { ok: false, error: err?.message || String(err) };
  }
}

module.exports = { sendEmail };
