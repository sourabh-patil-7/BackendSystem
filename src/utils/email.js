const nodemailer = require("nodemailer");
var Mailgen = require("mailgen");
require("dotenv").config();

// Nodemailer Smtp details, defined in .env
const transporter = nodemailer.createTransport({
  host: process.env.HOST,
  port: process.env.EPORT,
  secure: false,
  auth: {
    user: process.env.USER,
    pass: process.env.PASSWORD,
  },
});


// Initialize mailgen
const mailGenerator = new Mailgen({
  theme: "default",
  product: {
    // Appears in header & footer of e-mails
    name: "Authentication System",
    link: "Auth.local",
    // we can also add logo here
  },
});

// Generate Email html with otp details
function emailBodyGenerate(options) {
  let email = {
    body: {
      name: options.username,
      intro:
        "We received a request to reset the password for your account. If you made this request, please use this OTP code to reset the password",

      action: {
        instructions: "This Code only valid for 1 hour",
        button: {
          color: "#252525",
          text: options.otp,
          link: "#",
        },
      },
      outro:
        "Need help, or have questions? Contact our support, we'd love to help.",
    },
  };

  // Generate HTML email body
  const emailBody = mailGenerator.generate(email);
  return emailBody;
}

// send email to client
async function sendEmail(options, email) {
  const info = await transporter.sendMail({
    from: '"Auth" <test@merauth.local>', // sender address
    to: options.email, // list of receivers
    subject: options.subject, // Subject line
    // text: "Hello world?", // plain text body
    html: email, // html body
  });
}

module.exports = { sendEmail, emailBodyGenerate };
