const express = require('express');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const cors = require('cors'); 

const app = express();

app.use(cors());
app.use(express.json());

const otpStore = {};

// 1. Configure Gmail Transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    // We use process.env here for security when deploying to Render
    user: process.env.GMAIL_USER, 
    pass: process.env.GMAIL_APP_PASSWORD 
  }
});

// 2. Endpoint to Request OTP
app.post('/request-otp', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' });

  const otp = crypto.randomInt(100000, 999999).toString();
  const expiresAt = Date.now() + 5 * 60 * 1000;
  
  otpStore[email] = { otp, expiresAt };

  try {
    await transporter.sendMail({
      // The 'from' address should match your Gmail address to avoid spam filters
      from: `"Security Team" <${process.env.GMAIL_USER}>`,
      to: email,
      subject: `Your verification code is ${otp}`,
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Your Verification Code</title>
        </head>
        <body style="margin: 0; padding: 20px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f4f5f7; color: #333333;">
          <table align="center" width="100%" style="max-width: 500px; background-color: #ffffff; border-radius: 8px; border: 1px solid #e2e8f0; margin: 0 auto; padding: 32px; border-collapse: collapse;">
            <tr>
              <td>
                <!-- Header / Logo area -->
                <div style="text-align: center; margin-bottom: 24px;">
                  <h2 style="margin: 0; color: #0f172a; font-size: 24px;">Acme Corp</h2>
                </div>

                <h3 style="margin-top: 0; font-size: 18px; color: #1e293b;">Verify your email address</h3>
                <p style="font-size: 14px; line-height: 1.6; color: #475569; margin-bottom: 24px;">
                  You requested to verify your account. Please use the following one-time password (OTP) to complete your verification process.
                </p>

                <!-- OTP Box -->
                <div style="background-color: #f8fafc; border: 1px solid #cbd5e1; border-radius: 6px; padding: 16px; text-align: center; margin-bottom: 24px;">
                  <span style="font-family: 'Courier New', Courier, monospace; font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #0f172a;">
                    ${otp}
                  </span>
                </div>

                <p style="font-size: 14px; line-height: 1.6; color: #475569; margin-bottom: 24px;">
                  This code will expire in <strong>5 minutes</strong>.
                </p>

                <!-- Security Warning -->
                <p style="font-size: 12px; line-height: 1.5; color: #64748b; margin-bottom: 0;">
                  If you didn't request this code, you can safely ignore this email. Someone else might have typed your email address by mistake, and your account remains secure.
                </p>

                <hr style="border: 0; border-top: 1px solid #e2e8f0; margin: 24px 0;">

              </td>
            </tr>
          </table>
        </body>
        </html>
      `
    });
    
    console.log(`OTP sent to ${email} via Gmail`);
    res.json({ message: 'OTP sent successfully!' });
  } catch (error) {
    console.error('Error sending email:', error);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

// 3. Endpoint to Verify OTP
app.post('/verify-otp', (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) return res.status(400).json({ error: 'Email and OTP are required' });
  
  const record = otpStore[email];
  
  if (!record) {
    return res.status(400).json({ error: 'No OTP found for this email' });
  }

  if (Date.now() > record.expiresAt) {
    delete otpStore[email];
    return res.status(400).json({ error: 'OTP has expired' });
  }

  if (record.otp === otp) {
    delete otpStore[email]; 
    return res.json({ message: 'Success! OTP verified and user authenticated.' });
  } else {
    return res.status(400).json({ error: 'Invalid OTP' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
