const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'continental.auth@gmail.com',
    pass: 'roehxqkjjxmafadj' // no spaces, and don't commit this to GitHub
  }
});

function sendEmail(to, subject, html) {
  const mailOptions = {
    from: '"Continental ID" <continental.auth@gmail.com>',
    to,
    subject,
    html
  };

  return transporter.sendMail(mailOptions);
}

module.exports = sendEmail;

