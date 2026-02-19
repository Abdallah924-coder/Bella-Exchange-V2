const nodemailer = require('nodemailer');

let transporter;

function createTransporter() {
  if (transporter) return transporter;
  const host = process.env.SMTP_HOST;
  if (!host) {
    return null;
  }

  transporter = nodemailer.createTransport({
    host,
    port: Number(process.env.SMTP_PORT || 587),
    secure: String(process.env.SMTP_SECURE || 'false') === 'true',
    requireTLS: String(process.env.SMTP_REQUIRE_TLS || 'true') === 'true',
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
    return;
  }

  await transporter.sendMail({
    from: process.env.SMTP_FROM || 'noreply@bellaexchange.cg',
    to,
    subject,
    text,
    html,
    attachments
  });
}

module.exports = { sendEmail };
